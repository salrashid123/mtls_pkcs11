module main

go 1.20

require (
	github.com/ThalesIgnite/crypto11 v1.2.3
	github.com/salrashid123/mtls_pkcs11/signer/pkcs v0.0.0
	golang.org/x/net v0.0.0-20210415231046-e915ea6b2b7d
)

require (
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/text v0.3.6 // indirect
)

replace github.com/salrashid123/mtls_pkcs11/signer/pkcs => ./signer/pkcs
