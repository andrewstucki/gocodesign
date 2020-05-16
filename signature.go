package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/macho"
	"encoding/asn1"
	"encoding/binary"
	"errors"

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
	signedDataMagic        uint32        = 0xfade0b01
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

func signature(path string) ([]byte, []byte, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, nil, err
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
			return nil, nil, errors.New("invalid code signature")
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
		return nil, nil, errors.New("no signature found")
	}

	segment := f.Segment("__LINKEDIT")
	if segment == nil {
		return nil, nil, errors.New("invalid code signature linkedit segment not found")
	}

	data, err := segment.Data()
	if err != nil {
		return nil, nil, err
	}

	offset := int(cmd.DataOffset) - int(segment.Offset)
	signatureEnd := offset + int(cmd.DataSize)
	if len(data) < signatureEnd {
		return nil, nil, errors.New("invalid code signature segment too small")
	}
	signatureData := data[offset:signatureEnd]
	// order here independent of endianness?
	blob, err := readBlob(signatureData)
	if err != nil {
		return nil, nil, err
	}

	if blob.Magic != embeddedSignatureMagic {
		return nil, nil, errors.New("unable to find embedded signature")
	}

	var codeDirectory []byte
	var signature []byte
	for _, i := range blob.Index {
		if len(signatureData) < int(i.Offset) {
			return nil, nil, errors.New("invalid code signature invalid blob offset")
		}
		indexEntry := signatureData[i.Offset:]
		if len(indexEntry) < 8 {
			return nil, nil, errors.New("invalid code signature invalid blob data")
		}
		indexMagic := binary.BigEndian.Uint32(indexEntry[0:4])
		indexLength := binary.BigEndian.Uint32(indexEntry[4:8])
		if len(indexEntry) < int(indexLength) {
			return nil, nil, errors.New("invalid code signature invalid blob data")
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
		}
	}
	if signature != nil && codeDirectory != nil {
		return signature, codeDirectory, nil
	}
	return nil, nil, errors.New("code signature not found")
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

func verify(signature *pkcs7.PKCS7, codeDirectory []byte, truststore *x509.CertPool, crl *pkix.CertificateList) error {
	revocations := crl.TBSCertList.RevokedCertificates
	for _, cert := range signature.Certificates {
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

	// Apple code signatures use the first code directory
	// as the signature material
	signature.Content = codeDirectory

	return signature.VerifyWithChain(truststore)
}

func isRevoked(certs []pkix.RevokedCertificate, cert *x509.Certificate) bool {
	for _, revoked := range certs {
		if revoked.SerialNumber == cert.SerialNumber {
			return true
		}
	}
	return false
}
