gocodesign: bindata.go go.mod go.sum main.go signature.go
	go build -ldflags "-w" && upx -9 gocodesign

bindata.go:
	go generate

.PHONY: certs
certs: apple
	@curl -o apple/AppleIncRootCertificate.cer https://www.apple.com/appleca/AppleIncRootCertificate.cer
	@curl -o apple/root.crl https://www.apple.com/appleca/root.crl

apple:
	mkdir apple
