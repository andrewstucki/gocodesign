package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"os"
	"time"
)

//go:generate make certs
//go:generate go-bindata -nocompress -prefix apple apple

func main() {
	inParam := flag.String("f", "", "Specifies the Mach-O file to read")
	debugParam := flag.Bool("debug", false, "Gives more verbose output")

	flag.Parse()
	if *inParam == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	sig, err := signature(*inParam)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	pool, crl := truststore()
	if *debugParam {
		sig.Dump()
	}

	if crl.HasExpired(time.Now()) {
		fmt.Println("WARNING: using an expired CRL")
	}
	if err := sig.Verify(pool, crl); err != nil {
		fmt.Println("signature failed verification", err)
		os.Exit(1)
	}

	fmt.Println("signature verified")
}

func truststore() (*x509.CertPool, *pkix.CertificateList) {
	cert, err := x509.ParseCertificate(MustAsset("AppleIncRootCertificate.cer"))
	if err != nil {
		panic("invalid Apple root certificate stored")
	}
	crl, err := x509.ParseCRL(MustAsset("root.crl"))
	if err != nil {
		panic("invalid Apple root crl stored")
	}
	if err := cert.CheckCRLSignature(crl); err != nil {
		panic("invalid Apple root crl stored")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, crl
}
