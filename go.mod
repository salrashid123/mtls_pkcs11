module main

go 1.20

require (
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/salrashid123/mtls_pkcs11/signer/pkcs v0.0.0
	golang.org/x/net v0.26.0
)

require (
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/text v0.16.0 // indirect
)

replace github.com/salrashid123/mtls_pkcs11/signer/pkcs => ./signer/pkcs
