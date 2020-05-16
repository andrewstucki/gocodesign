package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/macho"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"go.mozilla.org/pkcs7"
)

// https://opensource.apple.com/source/Security/Security-55471/sec/Security/Tool/codesign.c
// https://opensource.apple.com/source/Security/Security-55471/sec/Security/SecCMS.c.auto.html
// https://github.com/unofficial-opensource-apple/Security/blob/bcd89df16fa72a2cddd20c65a934b2fa33748723/libsecurity_smime/lib/cmssiginfo.c#L667
// https://github.com/unofficial-opensource-apple/Security/blob/bcd89df16fa72a2cddd20c65a934b2fa33748723/libsecurity_smime/lib/cmssigdata.c#L553
// https://github.com/apple-open-source/macos/blob/7d4f8f3df0ddf54fdc04afd37573038b0979b5df/Security/OSX/libsecurity_codesigning/lib/StaticCode.cpp#L2354

const (
	loadCmdCodeSignature   macho.LoadCmd = 0x1d
	codeDirectoryMagic     uint32        = 0xfade0c02
	embeddedSignatureMagic uint32        = 0xfade0cc0
	entitlementsMagic      uint32        = 0xfade7171
	signedDataMagic        uint32        = 0xfade0b01
	entitlementSlot        uint32        = 5

	sha1HashType   uint8 = 0x1
	sha256HashType uint8 = 0x2
)

var (
	oidAppleDevIDExecute   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 13}
	oidAppleDevIDKernel    = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 18}
	oidAppleDevIDInstaller = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 14}
)

type linkEditCommand struct {
	Cmd  macho.LoadCmd
	Size uint32
	// file offset of data in __LINKEDIT segment
	DataOffset uint32
	// file size of data in __LINKEDIT segment
	DataSize uint32
}

type codeSignatureBlobIndex struct {
	Type   uint32
	Offset uint32
}

type codeSignatureSuperBlob struct {
	Magic  uint32
	Length uint32
	Count  uint32
	Index  []codeSignatureBlobIndex
}

type codeDirectory struct {
	Magic         uint32
	Length        uint32
	Version       uint32
	Flags         uint32
	HashOffset    uint32
	IdentOffset   uint32
	NSpecialSlots uint32
	NCodeSlots    uint32
	CodeLimit     uint32
	HashSize      uint8
	HashType      uint8
	Spare1        uint8
	PageSize      uint8
	Spare2        uint32
}

type codeSignatureInfo struct {
	signature          *pkcs7.PKCS7
	codeDirectory      *codeDirectory
	codeDirectoryData  []byte
	entitlementsHash   []byte
	entitlementsCDHash []byte
	entitlements       string
}

func signature(path string) (*codeSignatureInfo, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cmd *linkEditCommand
	byteOrder := f.ByteOrder
	for _, load := range f.Loads {
		data := load.Raw()
		cmdType := macho.LoadCmd(byteOrder.Uint32(data[0:4]))
		if cmdType != loadCmdCodeSignature {
			continue
		}
		if len(data) != 16 {
			return nil, errors.New("invalid code signature")
		}
		size := byteOrder.Uint32(data[4:8])
		dataOffset := byteOrder.Uint32(data[8:12])
		dataSize := byteOrder.Uint32(data[12:16])

		cmd = &linkEditCommand{
			Cmd:        cmdType,
			Size:       size,
			DataOffset: dataOffset,
			DataSize:   dataSize,
		}
		break
	}

	if cmd == nil {
		return nil, errors.New("no signature found")
	}

	segment := f.Segment("__LINKEDIT")
	if segment == nil {
		return nil, errors.New("invalid code signature linkedit segment not found")
	}

	data, err := segment.Data()
	if err != nil {
		return nil, err
	}

	offset := int(cmd.DataOffset) - int(segment.Offset)
	signatureEnd := offset + int(cmd.DataSize)
	if len(data) < signatureEnd {
		return nil, errors.New("invalid code signature segment too small")
	}
	signatureData := data[offset:signatureEnd]
	// order here independent of endianness?
	blob, err := readBlob(signatureData)
	if err != nil {
		return nil, err
	}

	if blob.Magic != embeddedSignatureMagic {
		return nil, errors.New("unable to find embedded signature")
	}

	var codeDirectory []byte
	var signature []byte
	var entitlementsData []byte
	var entitlements string
	for _, i := range blob.Index {
		if len(signatureData) < int(i.Offset) {
			return nil, errors.New("invalid code signature invalid blob offset")
		}
		indexEntry := signatureData[i.Offset:]
		if len(indexEntry) < 8 {
			return nil, errors.New("invalid code signature invalid blob data")
		}
		indexMagic := binary.BigEndian.Uint32(indexEntry[0:4])
		indexLength := binary.BigEndian.Uint32(indexEntry[4:8])
		if len(indexEntry) < int(indexLength) {
			return nil, errors.New("invalid code signature invalid blob data")
		}
		switch indexMagic {
		case signedDataMagic:
			signature = indexEntry[8:indexLength]
		case codeDirectoryMagic:
			if codeDirectory == nil {
				// we can actually have multiple code directories, just grab the first one
				// since that's what's used in calculating the digest for the signature
				codeDirectory = indexEntry[:indexLength]
			}
		case entitlementsMagic:
			entitlements = string(indexEntry[8:indexLength])
			entitlementsData = indexEntry[:indexLength]
		}
	}
	if signature != nil && codeDirectory != nil {
		pkcs, err := pkcs7.Parse(signature)
		if err != nil {
			return nil, err
		}

		directory, err := unmarshalCodeDirectory(codeDirectory)
		if err != nil {
			return nil, err
		}

		var entitlementsCDHash []byte
		var entitlementsHash []byte
		if entitlementsData != nil {
			hash, err := hashForType(directory.HashType)
			if err != nil {
				return nil, err
			}
			if _, err := hash.Write(entitlementsData); err != nil {
				return nil, err
			}
			entitlementsHash = hash.Sum(nil)
		}

		if directory.NSpecialSlots >= entitlementSlot {
			hashStart := directory.HashOffset - entitlementSlot*uint32(directory.HashSize)
			hashEnd := hashStart + uint32(directory.HashSize)
			if len(codeDirectory) < int(hashEnd) {
				return nil, errors.New("invalid code directory entitlement hash")
			}
			entitlementsCDHash = codeDirectory[hashStart:hashEnd]
		}

		return &codeSignatureInfo{
			signature:          pkcs,
			codeDirectory:      directory,
			codeDirectoryData:  codeDirectory,
			entitlements:       entitlements,
			entitlementsHash:   entitlementsHash,
			entitlementsCDHash: entitlementsCDHash,
		}, nil
	}
	return nil, errors.New("code signature not found")
}

func unmarshalCodeDirectory(data []byte) (*codeDirectory, error) {
	var directory codeDirectory
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &directory); err != nil {
		return nil, err
	}
	return &directory, nil
}

func readBlob(data []byte) (*codeSignatureSuperBlob, error) {
	if len(data) < 12 {
		return nil, errors.New("invalid signature")
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	length := binary.BigEndian.Uint32(data[4:8])
	count := binary.BigEndian.Uint32(data[8:12])
	indexData := data[12:]
	indices := make([]codeSignatureBlobIndex, count)
	for i := range indices {
		if len(indexData) < 8 {
			return nil, errors.New("invalid signature")
		}
		indices[i] = codeSignatureBlobIndex{
			Type:   binary.BigEndian.Uint32(indexData[0:4]),
			Offset: binary.BigEndian.Uint32(indexData[4:8]),
		}
		indexData = indexData[8:]
	}

	return &codeSignatureSuperBlob{
		Magic:  magic,
		Length: length,
		Count:  count,
		Index:  indices,
	}, nil
}

func hashForType(hashType uint8) (hash.Hash, error) {
	switch hashType {
	case sha1HashType:
		return sha1.New(), nil
	case sha256HashType:
		return sha256.New(), nil
	}
	return nil, errors.New("unsupported hash type")
}

func (c *codeSignatureInfo) Verify(truststore *x509.CertPool, crl *pkix.CertificateList) error {
	revocations := crl.TBSCertList.RevokedCertificates
	for _, cert := range c.signature.Certificates {
		if isRevoked(revocations, cert) {
			return errors.New("revoked certificate found")
		}
		unhandledCriticalExtensions := []asn1.ObjectIdentifier{}
		for _, unhandled := range cert.UnhandledCriticalExtensions {
			if !unhandled.Equal(oidAppleDevIDExecute) &&
				!unhandled.Equal(oidAppleDevIDKernel) &&
				!unhandled.Equal(oidAppleDevIDInstaller) {
				// strip out the apple-specific extensions
				// figure out if we should actually use these
				// to verify some other part of the binary
				unhandledCriticalExtensions = append(unhandledCriticalExtensions, unhandled)
			}
		}
		cert.UnhandledCriticalExtensions = unhandledCriticalExtensions
	}

	if subtle.ConstantTimeCompare(c.entitlementsHash, c.entitlementsCDHash) != 1 {
		return errors.New("entitlement hash mismatch")
	}

	// Apple code signatures use the first code directory
	// as the signature material
	c.signature.Content = c.codeDirectoryData

	return c.signature.VerifyWithChain(truststore)
}

func (c *codeSignatureInfo) Dump() {
	if c.entitlementsHash != nil {
		fmt.Printf("EntitlementsCDHash: %x\n", c.entitlementsCDHash)
		fmt.Printf("EntitlementsHash: %x\n", c.entitlementsHash)
	}
	for _, cert := range c.signature.Certificates {
		fmt.Println("Subject:", cert.Subject)
		fmt.Println("Issuer:", cert.Issuer)
	}
	if c.entitlements != "" {
		fmt.Printf("Entitlements:\n%s\n", c.entitlements)
	}
}

func isRevoked(certs []pkix.RevokedCertificate, cert *x509.Certificate) bool {
	for _, revoked := range certs {
		if revoked.SerialNumber == cert.SerialNumber {
			return true
		}
	}
	return false
}
