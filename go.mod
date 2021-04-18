module main

go 1.15

require (
	github.com/ThalesIgnite/crypto11 v1.2.3
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/salrashid123/mtls_pkcs11/signer/pkcs v0.0.0-20210418175523-0ab062d71a51 // indirect
	//github.com/salrashid123/mtls_pkcs11/signer/pkcs v0.0.0
	golang.org/x/net v0.0.0-20210415231046-e915ea6b2b7d // indirect
)

//replace github.com/salrashid123/mtls_pkcs11/signer/pkcs => ./signer/pkcs
