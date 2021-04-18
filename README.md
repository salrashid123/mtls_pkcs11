
## mTLS with PKCS11 

Sample application and library that establishes mTLS using keys stored in HSM/TPM/Yubikey via [PKCS-11 interface](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html).  Essentially this library and sample provides a way to use HSM/TPM/Yubikey embedded private keys for mTLS.  

To use this, you must configure the pkcs device to include a private key and then specify loading and using its corresponding PKCS module/driver.  Each type of pkcs device has its own driver that translates/brokers PKCS-11 API commands to its native interface.  For example, a Yubikey interface driver will need to be installed in order to access the device's keys by translating standard PKCS API calls to native driver directives for YubiKey.  Similar situation for any other HSM device or Trusted Platform Module (TPM).   

This library provides the same root golang interface which is used to access any PKCS target for mTLS.  We will be using the [crypto.Signer](https://golang.org/pkg/crypto/#Signer) implementation provided by [ThalesIgnite/crypto11](https://github.com/ThalesIgnite/crypto11) as the underlying command set.  [LetsEncrypt](https://github.com/letsencrypt/pkcs11key) also provides an interface but in this case, we'll just use the ready made Singer

This tutorial also installs openssl PKCS module which we will use to test.  You do not need to install openssl on each system during production since the underlying driver can handle the PKCS APIs on its own; we are just using openssl for testing.

>> NOTE: this repo is NOT supported by Google


>> This repo will demonstrate using SoftHSM mTLS but also shows the configurations for YubiKey and Trusted Platform Module

### References

* OpenSSL Provider
  - `/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so`:  OpenSSL Engine that allows dynamic PKCS11 providers

* PKCS11 Modules
  - `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`: [SoftHSM PKCS Driver](https://packages.ubuntu.com/xenial/libsofthsm2)
  - `/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1`: [TPM PKCS11 Driver](https://github.com/tpm2-software/tpm2-pkcs11)
  - `/usr/lib/x86_64-linux-gnu/libykcs11.so`:  [Yubikey PKCS Driver](https://developers.yubico.com/yubico-piv-tool/YKCS11/)
  - `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`:  Older PKCS11 provider for SmartCards.  [No longer required](https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html) for Yubikey 

- [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed):  mTLS with TPM backed keys using [go-tpm](https://github.com/google/go-tpm-tools).  This does not use PKCS11
- [crypto.Signer, crypto.Decrypter implementations](https://github.com/salrashid123/signer#usage-tls):  Various crypto.Sginer implementations that do not use PKCS11 and instead use native drivers.
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2): Samples for using TPMs in golang
- [YubiKeyTokenSource](https://github.com/salrashid123/yubikey): This implements a crypto.Signer for a yubikey by using yubikey APIs directly (not via PKCS11)!
- [Sample CA for mTLS](https://github.com/salrashid123/ca_scratchpad)
- [OpenSSL docker with TLS trace enabled (enable-ssl-trace)](https://github.com/salrashid123/openssl_trace)

Anyway, lets get started..

---

### Install PKCS11 support and Verify with OpenSSL

The following will install and test softHSM using openssl.  Once this is done, we will use the golang mTLS clients to establish client-server communication.

#### Install openssl with pkcs11 

First install openssl with its [PKCS11 engine](https://github.com/OpenSC/libp11#openssl-engines).

On debian

```bash
# add to /etc/apt/sources.list
  deb http://http.us.debian.org/debian/ testing non-free contrib main

# then
$ export DEBIAN_FRONTEND=noninteractive 
$ apt-get update && apt-get install libtpm2-pkcs11-1 tpm2-tools libengine-pkcs11-openssl opensc -y
```

Note, the installation above adds in the libraries for all modules in this repo (TPM, OpenSC, etc)..you may only need `libengine-pkcs11-openssl` here to verify

Once installed, you can check that it can be loaded:

Set the pkcs11 provider and module directly into openssl (make sure `libpkcs11.so` engine reference exists first!)

- `/etc/ssl/openssl.cnf`
```bash
openssl_conf = openssl_def
[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
```

```bash
$ ls /usr/lib/x86_64-linux-gnu/engines-1.1/
afalg.so  libpkcs11.so  padlock.so  pkcs11.la  pkcs11.so

$ openssl engine
  (rdrand) Intel RDRAND engine
  (dynamic) Dynamic engine loading support

$ openssl engine -t -c pkcs11
  (pkcs11) pkcs11 engine
  [RSA, rsaEncryption, id-ecPublicKey]
      [ available ]

      dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
```

---

#### SOFTHSM

SoftHSM is as the name suggests, a sofware "HSM" module used for testing.   It is ofcourse not hardware backed but the module does allow for a PKCS11 interface which we will also use for testing.

First make sure the softhsm library is installed

- [SoftHSM Install](https://www.opendnssec.org/softhsm/)

Setup a config file where the `directories.tokendir` points to a existing folder where softHSM will save all its data (in this case its `misc/tokens/`)

>> This repo already contains a sample configuration/certs to use with the softhsm token directory...just delete the folder and start from scratch if you want..

```bash
cd misc
mkdir tokens
```

Edit `misc/softhsm.conf`
and edit the value for `directories.tokendir`

```bash
log.level = DEBUG
objectstore.backend = file
directories.tokendir = /absolute/path/to/pkcs11_signer/misc/tokens/
slots.removable = true
```

Now, make sure that the installation created the softhsm module for openssl:  `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`

```bash
openssl engine dynamic \
 -pre SO_PATH:/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so \
 -pre ID:pkcs11 -pre LIST_ADD:1 \
 -pre LOAD \
 -pre MODULE_PATH:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
 -t -c

  (dynamic) Dynamic engine loading support
  [Success]: SO_PATH:/usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
  [Success]: ID:pkcs11
  [Success]: LIST_ADD:1
  [Success]: LOAD
  [Success]: MODULE_PATH:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
  Loaded: (pkcs11) pkcs11 engine
  [RSA, rsaEncryption, id-ecPublicKey]
      [ available ] 
```

Use [pkcs11-too](https://manpages.debian.org/testing/opensc/pkcs11-tool.1.en.html) which comes with the installation of opensc

```bash
export SOFTHSM2_CONF=/absolute/path/to/pkcs11_signer/misc/softhsm.conf

## init softhsm
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"

## Change pin and list token slots
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots
        Available slots:
        Slot 0 (0x51b9d639): SoftHSM slot ID 0x51b9d639
        token label        : token1
        token manufacturer : SoftHSM project
        token model        : SoftHSM v2
        token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
        hardware version   : 2.6
        firmware version   : 2.6
        serial num         : 11819f2dd1b9d639
        pin min/max        : 4/255

# Create object
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type rsa:2048 --id 4142 --label keylabel1 --pin mynewpin

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects
        Using slot 0 with a present token (0x51b9d639)
        Public Key Object; RSA 2048 bits
        label:      keylabel1
        ID:         4142
        Usage:      encrypt, verify, wrap
        Access:     local

### use key to generate random bytes

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="keylabel1" --pin mynewpin --generate-random 50 | xxd -p

### Use openssl module to sign and print the public key (not, your serial number will be different)
export PKCS11_PRIVATE_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=11819f2dd1b9d639;token=token1;type=private;object=keylabel1?pin-value=mynewpin"
export PKCS11_PUBLIC_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=11819f2dd1b9d639;token=token1;type=public;object=keylabel1?pin-value=mynewpin"

### Sign and verify
echo "sig data" > "data.txt"
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout -out pub.pem
openssl pkeyutl -engine pkcs11 -keyform engine -inkey $PKCS11_PRIVATE_KEY -sign -in data.txt -out data.sig
openssl pkeyutl -pubin -inkey pub.pem -verify -in data.txt -sigfile data.sig

### Display the public key
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout
```

#### Generate mTLS certs

At this point, we can use the embedded private keys to generate x509 certificate CSRs. Note: devices can already generate x509 certs associated with  its private key but in this case, we will use an externally generated CA using the private key alone

```bash
git clone https://github.com/salrashid123/ca_scratchpad
cd ca_scratchpad
```

follow the three steps as described in `ca_scratchpad/README.md`:  

- Create Root CA
- Gen CRL
- Create Subordinate CA for TLS Signing

stop after setting up the CA

Now that the CA is setup, we need to create a CSR using the private key in the SoftHSM

```bash
export SOFTHSM2_CONF=/absolute/path/to/pkcs11_signer/misc/softhsm.conf
cd csr/

## you will see the CSR based on the private key in SoftHSM (your cert will be different!)
$ go run csr/csr.go 
-----BEGIN CERTIFICATE REQUEST-----
MIIC7DCCAdQCAQAwejELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
FjAUBgNVBAcTDU1vdW50YWluIFZpZXcxDzANBgNVBAoTBkdvb2dsZTETMBEGA1UE
CxMKRW50ZXJwcmlzZTEYMBYGA1UEAxMPcGtjcy5kb21haW4uY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGAmiw+2vke+9uy/zstyK56WcASTxL6s
wxmGG1lIs2T0tsoG4/Kqw253hHR86wc8TTmLq02JMSrCYb2PAUmTQjOc5ReL2P4N
wxRGYGOV9NRCGev4+o45ly5/buhifznFljsObJvp/bPRnKkRrCM4YettGKunJWLH
g6fVSFscPdVt6SVLfh0niT6KPbYhYeDynCUbuNtCIebnWpT6UcJU01Bdp6yQ5o14
pcHhk6+gAq/a3/TfpMsMSje+iaUQTf4pBnYWVhAoOwWxp3TZ224N6cnTCdVYUdfq
Jps2cUSYOgJ/OqxE7dlF0p0QJzBXZDg4DO4lx2vT86RHF6lO1MSheQIDAQABoC0w
KwYJKoZIhvcNAQkOMR4wHDAaBgNVHREEEzARgg9wa2NzLmRvbWFpbi5jb20wDQYJ
KoZIhvcNAQELBQADggEBAAZMeiVH9HT9Ghn3GC7+83NIQSEI97vgo9tMPTysujSV
UaPBJYbVpSeE9B1fYVvcPuyHrV9/tQHunpbjJU5ZEsqfE8LEq2AcxKfPNSpWxl3F
dyRigSQc/GN3QDNZsSI1VKTjiYZ5yZhhSmZqL3S5BMY43tu5a3IV3hDuDk8GRovg
+gEWf2/z2NluqEwMuER0h7ltTX27qkk+d443EtSrwN50hSnqD6fMvfjcwbYq2Sw8
tOjt5lkQREgw2GFjObMr2w1IZXPy7bHDZYixUVZw4sizztHSuKK9yN5zPh6rzLAZ
jwPri7o275SdaSxZ7CmawSaeL0S33NJfHGAy5IeXngM=
-----END CERTIFICATE REQUEST-----
```

copy paste theCSR into files called 

* `ca_cratchpad/certs/softhsm-server.csr`
* `ca_cratchpad/certs/softhsm-client.csr`
  (yes, we're going to use the same csr for both end just to test for simplicity)

Generate Certs
```bash
cd ca_scratchpad
export NAME=softhsm-server
export SAN=DNS:pkcs.domain.com
openssl ca \
    -config tls-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -extensions server_ext


export NAME=softhsm-client
export SAN=DNS:pkcs.domain.com

openssl ca \
    -config tls-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -policy extern_pol \
    -extensions client_ext
```

You can also directly use openssl to create the CSR and then embed the cert into the HSM:

```bash
export PKCS11_PRIVATE_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=11819f2dd1b9d639;token=token1;type=private;object=keylabel1?pin-value=mynewpin"
export PKCS11_PUBLIC_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=11819f2dd1b9d639;token=token1;type=public;object=keylabel1?pin-value=mynewpin"

openssl req -new -x509 -config tls-ca.conf -extensions server_ext -engine pkcs11 -keyform engine -key "$PKCS11_PRIVATE_KEY" -outform pem -out certs/$NAME.crt
```

then after install, you should see two objects (public key, and a cert)

```bash
$ openssl x509 -in certs/$NAME.crt -out certs/$NAME.der -outform DER
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l --id 4142 --label keylabel1 -y cert -w certs/$NAME.der --pin mynewpin

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects
    Using slot 0 with a present token (0x451f46c3)
    Certificate Object; type = X.509 cert
      label:      keylabel1
      subject:    DN: C=US, ST=California, L=Mountain View, O=Google, OU=Enterprise, CN=pkcs.domain.com
      ID:         4142
    Public Key Object; RSA 2048 bits
      label:      keylabel1
      ID:         4142
      Usage:      encrypt, verify, wrap
      Access:     local
```

### golang mTLS

We're finally ready to use the private key in the PKCS device and the x509 which we generated externally:

First to setup and use this library, we will need to configure the PKCS provider and surface [tls.Config](https://golang.org/pkg/crypto/tls/#Config) that handles the traffic and cert-signing:


For softHSM Server:

```golang
import (
  salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"
)
...
...

	// export SOFTHSM2_CONF=/absolute/path/to/pkcs11_signer/misc/softhsm.conf
	config := &crypto11.Config{
		Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		TokenLabel: "token1",
		Pin:        "mynewpin",
	}
  ctx, err := crypto11.Configure(config)
	clientCaCert, err := ioutil.ReadFile("ca_scratchpad/ca/tls-ca-chain.pem")
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	r, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
		Context:        ctx,
		PkcsId:         nil,                                      //softhsm
		PkcsLabel:      []byte("keylabel1"),                      //softhsm
		PublicCertFile: "ca_scratchpad/certs/softhsm-server.crt", //softhsm, you can omit this parameter if you have the x509 on the HSM device
		ExtTLSConfig: &tls.Config{
			RootCAs:    clientCaCertPool,
			ClientCAs:  clientCaCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
  }) 
  
	var server *http.Server
	server = &http.Server{
		Addr:      ":8081",
		TLSConfig: r.TLSConfig(),
	}  
```

Note, we are specifying the `PublicCertFile` directly...hardware like YubiKeys can use embedded x509 certs.  If the device supports the cert, omit this parameter. 

Run Server
```bash
export SOFTHSM2_CONF=/absolute/path/to/pkcs11_signer/misc/softhsm.conf
go run server/server.go
```

Run Client
```bash
export SOFTHSM2_CONF=/absolute/path/to/pkcs11_signer/misc/softhsm.conf
go run client/client.go
```

### curl mTLS

To use curl for client certs, you can use the `--engine` directive and specify that the private key referenced to by the `PKCS11_PRIVATE_KEY` uri

```bash
export SOFTHSM2_CONF=/absolute/path/to/pkcs11_signer/misc/softhsm.conf
export PKCS11_PRIVATE_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=11819f2dd1b9d639;token=token1;type=private;object=keylabel1?pin-value=mynewpin"
export PKCS11_PUBLIC_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=11819f2dd1b9d639;token=token1;type=public;object=keylabel1?pin-value=mynewpin"

curl -vvv -tls13  --cacert ca_scratchpad/ca/tls-ca-chain.pem \
   --cert ca_scratchpad/certs/softhsm-client.crt  --engine pkcs11  --key-type ENG --key "$PKCS11_PUBLIC_KEY"  \
   --resolve pkcs.domain.com:8081:127.0.0.1   -H "host: pkcs.domain.com" \
         https://pkcs.domain.com:8081/
```

---

### Appendix

The following describes using `pkcs11-tool` to setup the mTLS configuration for YubiKey and TPM:

#### Yubikey

Install module references for openssc-pkcs11.so and `libykcs11.so`

- [OpenSC’s pkcs11-tool](https://developers.yubico.com/yubico-piv-tool/YKCS11/Supported_applications/pkcs11tool.html)
- [OpenSSL with YubiHSM 2 via engine_pkcs11 and yubihsm_pkcs11](https://developers.yubico.com/YubiHSM2/Usage_Guides/OpenSSL_with_pkcs11_engine.html)

The following assumes you already setup a KeyPair on the Yubikey using the commands above

```bash
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libykcs11.so --list-objects

Public Key Object; RSA 2048 bits
  label:      Public key for Digital Signature
  ID:         02
  Usage:      encrypt, verify

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  --list-token-slots 
    Available slots:
    Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID 00 00
      token label        : user1_esodemoapp2_com
      token manufacturer : piv_II
      token model        : PKCS#15 emulated
      token flags        : login required, rng, token initialized, PIN initialized
      hardware version   : 0.0
      firmware version   : 0.0
      serial num         : 993084513cb2a39d
      pin min/max        : 4/8


$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  --list-objects
    Using slot 0 with a present token (0x0)
    Public Key Object; RSA 2048 bits
      label:      PIV AUTH pubkey
      ID:         01
      Usage:      encrypt, verify, wrap
      Access:     none
    Certificate Object; type = X.509 cert
      label:      Certificate for PIV Authentication
      subject:    DN: C=US, O=Google, OU=Enterprise, CN=user1_esodemoapp2_com
      ID:         01
    Public Key Object; RSA 2048 bits
      label:      SIGN pubkey
      ID:         02
      Usage:      encrypt, verify, wrap
      Access:     none
    Certificate Object; type = X.509 cert
      label:      Certificate for Digital Signature
      subject:    DN: C=US, O=Google, OU=Enterprise, CN=yubikey-svc@mineral-minutia-820.iam.gserviceaccount.com
      ID:         02
    Public Key Object; RSA 2048 bits
      label:      KEY MAN pubkey
      ID:         03
      Usage:      encrypt
      Access:     none
    Certificate Object; type = X.509 cert
      label:      Certificate for Key Management
      subject:    DN: C=US, O=Google, OU=Enterprise, CN=user1@esodemoapp2.com
      ID:         03


$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --label="SIGN pubkey" --pin 123456 --generate-random 50 | xxd -p
Using slot 0 with a present token (0x0)
c621e081d3a0ed5c10f1dceea80380785612b792697242802c85ec1b6fc7
6b83dd4f00c002edb526f6d6e3ab63e407c643af


export PKCS11_PRIVATE_KEY="pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=993084513cb2a39d;token=user1_esodemoapp2_com;type=private;id=%02?pin-value=123456"
export PKCS11_PUBLIC_KEY="pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=993084513cb2a39d;token=user1_esodemoapp2_com;type=public;id=%02?pin-value=123456"

### Display the public key
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout

### Sign and verify
echo "sig data" > "data.txt"
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout -out pub.pem
openssl pkeyutl -engine pkcs11 -keyform engine -inkey $PKCS11_PRIVATE_KEY -sign -in data.txt -out data.sig
openssl pkeyutl -pubin -inkey pub.pem -verify -in data.txt -sigfile data.sig
```

#### TPM

To use a TPM, you must have a machine with a TPM installed (ofcourse)...for example a Google Cloud Shielded VM.  Your laptop also likely has one but i'd recommend not messing around with it

- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2): Samples for using TPMs in golang
- [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed):  mTLS with TPM backed keys using [go-tpm](https://github.com/google/go-tpm-tools).  This does not use PKCS11


```bash
$ vi /etc/apt/sources.list
  deb http://http.us.debian.org/debian/ testing non-free contrib main

$ export DEBIAN_FRONTEND=noninteractive 
$ apt-get update && apt-get install libtpm2-pkcs11-1 tpm2-tools libengine-pkcs11-openssl opensc -y
```

Now use `pkcs-tools` to genrate a keypair...you can also import one or reference one thats already present..but the following creates one from scratch:

```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --slot-index=0 --init-token --label="token1" --so-pin="mysopin"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --label="token1" --init-pin --so-pin mysopin --pin mynewpin
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --list-token-slots
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --label="keylabel1" --login  --pin=mynewpin --id 0  --keypairgen --key-type rsa:2048

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1  --label="keylabel1" --pin mynewpin --generate-random 50 | xxd -p

$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --list-slots
    Available slots:
    Slot 0 (0x1): token1                          GOOG
    token label        : token1
    token manufacturer : GOOG
    token model        : vTPM
    token flags        : login required, rng, token initialized, PIN initialized
    hardware version   : 1.42
    firmware version   : 22.17
    serial num         : 0000000000000000
    pin min/max        : 0/128
    Slot 1 (0x2):                                 GOOG
    token state:   uninitialized


$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1 --list-objects

  Using slot 0 with a present token (0x1)
  Public Key Object; RSA 2048 bits
    label:      keylabel1
    Usage:      encrypt, verify
    Access:     local
```

Specify the MODULE for tpm in `/etc/ssl/openssl.cnf`

```bash
openssl_conf = openssl_def
[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
MODULE_PATH = /usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1
```

```bash
export PKCS11_PUBLIC_KEY="pkcs11:model=vTPM;manufacturer=GOOG;serial=0000000000000000;token=token1;type=public;object=keylabel1?pin-value=mynewpin"
export PKCS11_PRIVATE_KEY="pkcs11:model=vTPM;manufacturer=GOOG;serial=0000000000000000;token=token1;type=private;object=keylabel1?pin-value=mynewpin"

### Display the public key

openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout

### Sign and verify

echo "sig data" > "data.txt"
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_PUBLIC_KEY" -pubout -out pub.pem
openssl pkeyutl -engine pkcs11 -keyform engine -inkey $PKCS11_PRIVATE_KEY -sign -in data.txt -out data.sig
openssl pkeyutl -pubin -inkey pub.pem -verify -in data.txt -sigfile data.sig
```

