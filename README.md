
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
$ apt-get update && apt-get install libtpm2-pkcs11-1 tpm2-tools libengine-pkcs11-openssl opensc softhsm2 libsofthsm2 -y
```

Note, the installation above adds in the libraries for all modules in this repo (TPM, OpenSC, etc)..you may only need `libengine-pkcs11-openssl` here to verify

Once installed, you can check that it can be loaded:

Set the pkcs11 provider and module directly into openssl (make sure `libpkcs11.so` engine reference exists first!)


Verify the path,

```bash
$ ls /usr/lib/x86_64-linux-gnu/engines-3/
## or
$ ls /usr/lib/x86_64-linux-gnu/engines-1.1/


edit `/etc/ssl/openssl.cnf`
```bash
openssl_conf = openssl_def
[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so
```


```bash
$ openssl engine
  (rdrand) Intel RDRAND engine
  (dynamic) Dynamic engine loading support

$ openssl engine -t -c pkcs11
  (pkcs11) pkcs11 engine
  [RSA, rsaEncryption, id-ecPublicKey]
      [ available ]
```

---

#### SOFTHSM

SoftHSM is as the name suggests, a sofware "HSM" module used for testing.   It is ofcourse not hardware backed but the module does allow for a PKCS11 interface which we will also use for testing.

First make sure the softhsm library is installed

- [SoftHSM Install](https://www.opendnssec.org/softhsm/)

Setup a config file where the `directories.tokendir` points to a existing folder where softHSM will save all its data (in this case its `misc/tokens/`)

>> This repo already contains a sample configuration/certs to use with the softhsm token directory...just delete the folder and start from scratch if you want..

Now, make sure that the installation created the softhsm module for openssl:  `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`

```bash
openssl engine dynamic \
 -pre SO_PATH:/usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so \
 -pre ID:pkcs11 -pre LIST_ADD:1 \
 -pre LOAD \
 -pre MODULE_PATH:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
 -t -c

  (dynamic) Dynamic engine loading support
  [Success]: SO_PATH:/usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so
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
export SOFTHSM2_CONF=/absolute/path/to/mtls_pkcs11/misc/softhsm.conf
rm -rf /tmp/tokens
mkdir /tmp/tokens

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots
        Available slots:
        Slot 0 (0x2593104d): SoftHSM slot ID 0x2593104d
          token label        : token1
          token manufacturer : SoftHSM project
          token model        : SoftHSM v2
          token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
          hardware version   : 2.6
          firmware version   : 2.6
          serial num         : 2c6106832593104d
          pin min/max        : 4/255
        Slot 1 (0x1): SoftHSM slot ID 0x1
          token state:   uninitialized



### >>> Important NOTE the serial num   2c6106832593104d  
## we will use this in the PKCS-11 URI

# Create Server's private key as id=4142, keylabel1;  client as id=4143, keylabel2
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type rsa:2048 --id 4142 --label keylabel1 --pin mynewpin
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -k --key-type rsa:2048 --id 4143 --label keylabel2 --pin mynewpin

pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects

## get the serial number from the previous --list-token-slots command
export serial_number="2c6106832593104d"
### Use openssl module to sign and print the public key (not, your serial number will be different)
# server
export PKCS11_SERVER_PRIVATE_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=$serial_number;token=token1;type=private;object=keylabel1?pin-value=mynewpin"
export PKCS11_SERVER_PUBLIC_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=$serial_number;token=token1;type=public;object=keylabel1?pin-value=mynewpin"

# client
export PKCS11_CLIENT_PRIVATE_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=$serial_number;token=token1;type=private;object=keylabel2?pin-value=mynewpin"
export PKCS11_CLIENT_PUBLIC_KEY="pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=$serial_number;token=token1;type=public;object=keylabel2?pin-value=mynewpin"

### Display the public keys
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_SERVER_PUBLIC_KEY" -pubout
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_CLIENT_PUBLIC_KEY" -pubout

### Sign and verify
echo "sig data" > "data.txt"
openssl rsa -engine pkcs11  -inform engine -in "$PKCS11_SERVER_PUBLIC_KEY" -pubout -out pub.pem
openssl pkeyutl -engine pkcs11 -keyform engine -inkey $PKCS11_SERVER_PRIVATE_KEY -sign -in data.txt -out data.sig
openssl pkeyutl -pubin -inkey pub.pem -verify -in data.txt -sigfile data.sig
```

#### Generate mTLS certs

At this point, we can use the embedded private keys to generate x509 certificate CSRs. Note: devices can already generate x509 certs associated with  its private key but in this case, we will use an externally generated CA using the private key alone


Using a sample CA,

- Generate CSR

```bash
export SOFTHSM2_CONF=/absolute/path/to/pkcs11_signer/misc/softhsm.conf

$ go run csr/csr.go --csrFile=ca_scratchpad/certs/softhsm-server.csr --sni server.domain.com --keyLabel=keylabel1
$ go run csr/csr.go --csrFile=ca_scratchpad/certs/softhsm-client.csr --sni client.domain.com --keyLabel=keylabel2
```

- Generate Certs
```bash
cd ca_scratchpad/

export NAME=softhsm-server
export SAN=DNS:server.domain.com

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -extensions server_ext  


## generate client cert
export NAME=softhsm-client
export SAN=DNS:client.domain.com

openssl ca \
    -config single-root-ca.conf \
    -in certs/$NAME.csr \
    -out certs/$NAME.crt \
    -policy extern_pol \
    -extensions client_ext
```


- Upload the certs to the server:

```bash
export NAME=softhsm-server
openssl x509 -in certs/$NAME.crt -out certs/$NAME.der -outform DER
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l --id 4142 --label keylabel1 -y cert -w certs/$NAME.der --pin mynewpin

export NAME=softhsm-client
openssl x509 -in certs/$NAME.crt -out certs/$NAME.der -outform DER
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l --id 4143 --label keylabel2 -y cert -w certs/$NAME.der --pin mynewpin

## list the objects..you sould now see certificates too
$ pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects

      Using slot 0 with a present token (0x1ce44146)
      Certificate Object; type = X.509 cert
        label:      keylabel2
        subject:    DN: C=US, ST=California, L=Mountain View, O=Google, OU=Enterprise, CN=client.domain.com
        serial:     05
        ID:         4143
      Public Key Object; RSA 2048 bits
        label:      keylabel2
        ID:         4143
        Usage:      encrypt, verify, verifyRecover, wrap
        Access:     local
      Public Key Object; RSA 2048 bits
        label:      keylabel1
        ID:         4142
        Usage:      encrypt, verify, verifyRecover, wrap
        Access:     local
      Certificate Object; type = X.509 cert
        label:      keylabel1
        subject:    DN: C=US, ST=California, L=Mountain View, O=Google, OU=Enterprise, CN=server.domain.com
        serial:     04
        ID:         4142

```

### golang mTLS

We're finally ready to use the private key in the PKCS device and the x509 which we generated externally:

First to setup and use this library, we will need to configure the PKCS provider and surface [tls.Config](https://golang.org/pkg/crypto/tls/#Config) that handles the traffic and cert-signing:


For softHSM Server:

```golang
import (
  salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"
)

	// export SOFTHSM2_CONF=/absolute/path/to/pkcs11_signer/misc/softhsm.conf
	config := &crypto11.Config{
		Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		TokenLabel: "token1",
		Pin:        "mynewpin",
	}
  ctx, err := crypto11.Configure(config)
	clientCaCert, err := ioutil.ReadFile("ca_scratchpad/ca/root-ca.crt")
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
curl -vvv -tls13  --cacert ca_scratchpad/ca/root-ca.crt \
   --cert ca_scratchpad/certs/softhsm-client.crt  --engine pkcs11  --key-type ENG --key "$PKCS11_CLIENT_PRIVATE_KEY"  \
   --resolve server.domain.com:8081:127.0.0.1   -H "host: server.domain.com" \
         https://server.domain.com:8081/
```

---

- [mTLS with TPM bound private key](https://github.com/salrashid123/go_tpm_https_embed):  mTLS with TPM backed keys using [go-tpm](https://github.com/google/go-tpm-tools).  This does not use PKCS11
- [crypto.Signer, crypto.Decrypter implementations](https://github.com/salrashid123/signer#usage-tls):  Various crypto.Sginer implementations that do not use PKCS11 and instead use native drivers.
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2): Samples for using TPMs in golang
- [YubiKeyTokenSource](https://github.com/salrashid123/yubikey): This implements a crypto.Signer for a yubikey by using yubikey APIs directly (not via PKCS11)!
- [Sample CA for mTLS](https://github.com/salrashid123/ca_scratchpad)
- [OpenSSL docker with TLS trace enabled (enable-ssl-trace)](https://github.com/salrashid123/openssl_trace)
