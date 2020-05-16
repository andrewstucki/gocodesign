package main

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/macho"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

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
	}
	for _, signer := range signature.Signers {
		var signerCert *x509.Certificate
		for _, cert := range signature.Certificates {
			if cert.SerialNumber.Cmp(signer.IssuerAndSerialNumber.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, signer.IssuerAndSerialNumber.IssuerName.FullBytes) {
				signerCert = cert
				break
			}
		}
		if signerCert == nil {
			return errors.New("no certificate for signer")
		}

		var digest []byte
		for _, attribute := range signer.AuthenticatedAttributes {
			if attribute.Type.Equal(pkcs7.OIDAttributeMessageDigest) {
				if _, err := asn1.Unmarshal(attribute.Value.Bytes, &digest); err != nil {
					return err
				}
				break
			}
		}
		hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
		if err != nil {
			return err
		}
		h := hash.New()
		h.Write(codeDirectory)
		computed := h.Sum(nil)
		if subtle.ConstantTimeCompare(digest, computed) != 1 {
			return &pkcs7.MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
		}

		encodedAttributes, err := asn1.Marshal(struct {
			Attributes interface{} `asn1:"set"`
		}{Attributes: signer.AuthenticatedAttributes})
		if err != nil {
			return err
		}
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(encodedAttributes, &raw); err != nil {
			return err
		}
		signedData := raw.Bytes
		signingTime := time.Now().UTC()
		for _, attribute := range signer.AuthenticatedAttributes {
			if attribute.Type.Equal(pkcs7.OIDAttributeSigningTime) {
				if _, err := asn1.Unmarshal(attribute.Value.Bytes, &signingTime); err != nil {
					return err
				}
				break
			}
		}
		// signing time found, performing validity check
		if signingTime.After(signerCert.NotAfter) || signingTime.Before(signerCert.NotBefore) {
			return fmt.Errorf("signing time %q is outside of certificate validity %q to %q",
				signingTime.Format(time.RFC3339),
				signerCert.NotBefore.Format(time.RFC3339),
				signerCert.NotBefore.Format(time.RFC3339))
		}
		if truststore != nil {
			_, err = verifyCertChain(signerCert, signature.Certificates, truststore, signingTime)
			if err != nil {
				return err
			}
		}
		algo, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
		if err != nil {
			return err
		}
		if err := signerCert.CheckSignature(algo, signedData, signer.EncryptedDigest); err != nil {
			return err
		}
	}
	return nil
}

func verifyCertChain(signerCert *x509.Certificate, certs []*x509.Certificate, truststore *x509.CertPool, currentTime time.Time) (chains [][]*x509.Certificate, err error) {
	intermediates := x509.NewCertPool()
	for _, intermediate := range certs {
		unhandledCriticalExtensions := []asn1.ObjectIdentifier{}
		for _, unhandled := range intermediate.UnhandledCriticalExtensions {
			if !unhandled.Equal(oidAppleDevIDExecute) &&
				!unhandled.Equal(oidAppleDevIDKernel) &&
				!unhandled.Equal(oidAppleDevIDInstaller) {
				// strip out the apple-specific extensions
				// figure out if we should actually use these
				// to verify some other part of the binary
				unhandledCriticalExtensions = append(unhandledCriticalExtensions, unhandled)
			}
		}
		intermediate.UnhandledCriticalExtensions = unhandledCriticalExtensions
		intermediates.AddCert(intermediate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         truststore,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   currentTime,
	}
	chains, err = signerCert.Verify(verifyOptions)
	if err != nil {
		return chains, fmt.Errorf("failed to verify certificate chain: %v", err)
	}
	return
}

func getHashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA1), oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA1),
		oid.Equal(pkcs7.OIDDigestAlgorithmDSA), oid.Equal(pkcs7.OIDDigestAlgorithmDSASHA1),
		oid.Equal(pkcs7.OIDEncryptionAlgorithmRSA):
		return crypto.SHA1, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA256), oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA256):
		return crypto.SHA256, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA384), oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA384):
		return crypto.SHA384, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA512), oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA512):
		return crypto.SHA512, nil
	}
	return crypto.Hash(0), pkcs7.ErrUnsupportedAlgorithm
}

func getSignatureAlgorithm(digestEncryption, digest pkix.AlgorithmIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case digestEncryption.Algorithm.Equal(pkcs7.OIDDigestAlgorithmECDSASHA1):
		return x509.ECDSAWithSHA1, nil
	case digestEncryption.Algorithm.Equal(pkcs7.OIDDigestAlgorithmECDSASHA256):
		return x509.ECDSAWithSHA256, nil
	case digestEncryption.Algorithm.Equal(pkcs7.OIDDigestAlgorithmECDSASHA384):
		return x509.ECDSAWithSHA384, nil
	case digestEncryption.Algorithm.Equal(pkcs7.OIDDigestAlgorithmECDSASHA512):
		return x509.ECDSAWithSHA512, nil
	case digestEncryption.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSA),
		digestEncryption.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA1),
		digestEncryption.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA256),
		digestEncryption.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA384),
		digestEncryption.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA512):
		switch {
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA1):
			return x509.SHA1WithRSA, nil
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256):
			return x509.SHA256WithRSA, nil
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA384):
			return x509.SHA384WithRSA, nil
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA512):
			return x509.SHA512WithRSA, nil
		default:
			return -1, fmt.Errorf("unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(pkcs7.OIDDigestAlgorithmDSA),
		digestEncryption.Algorithm.Equal(pkcs7.OIDDigestAlgorithmDSASHA1):
		switch {
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA1):
			return x509.DSAWithSHA1, nil
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256):
			return x509.DSAWithSHA256, nil
		default:
			return -1, fmt.Errorf("unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmECDSAP256),
		digestEncryption.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmECDSAP384),
		digestEncryption.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmECDSAP521):
		switch {
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA1):
			return x509.ECDSAWithSHA1, nil
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256):
			return x509.ECDSAWithSHA256, nil
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA384):
			return x509.ECDSAWithSHA384, nil
		case digest.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA512):
			return x509.ECDSAWithSHA512, nil
		default:
			return -1, fmt.Errorf("unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	default:
		return -1, fmt.Errorf("unsupported algorithm %q",
			digestEncryption.Algorithm.String())
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
