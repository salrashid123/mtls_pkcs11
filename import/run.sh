export SOFTHSM2_CONF=/path/to/mtls_pkcs11/misc/softhsm.conf
rm -rf ../misc/tokens
mkdir ../misc/tokens
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

#go run aes_rsa/import.go
go run rsa_aes/import.go
#go run rsa_rsa/import.go

#pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
