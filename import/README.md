
## Wrap/Unwrap PKCS11 RSA and AES keys

Examples on how to wrap and unwrap an AES and RSA keys into softHSM


```bash
export SOFTHSM2_CONF=/path/to/mtls_pkcs11/misc/softhsm.conf

# list uspported mechanisms
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-mechanisms --slot-index 0
```

## Wrapping RSA key with AES key

see `rsa_aes/import.go`:

In this mode, we will:

1. Create AES key which is enabled for wrapping
```golang
	aesKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // we don't need to extract this..
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, make([]byte, 32)), /* KeyLength */
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "WrappingAESKey"), /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
```

2. Use it to encrypt/decrypt some sample data

THis is just to test, its not necessary for wrap/unwrap

3. Create RSA keypair enabled for extraction

```golang
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "pub1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, pubID),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "priv1"),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, privID),
	}

```

4. Sign and verify data with the RSA key

This is just for testing; its not necessary for wrapping


5. Wrap the RSA key with AES key

```golang
	wrappedPrivBytes, err := p.WrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)}, aesKey, pvk)
```

6. Unwrap the RSA key with the AES key

```golang
	ik, err := p.UnwrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)}, aesKey, wrappedPrivBytes, importedPrivateKeyTemplate)
```

7. Use the unwrapped key to sign/verify

Since its the same key we used, we should see the same signature as step 4

```log
$ go run aes_rsa/import.go 
CryptokiVersion.Major 2
2021/05/17 19:30:37 Created AES Key: 2
2021/05/17 19:30:37 Encrypted IV+Ciphertext 6xEZldVQCbL/uahW2I68nUG35HUVrPZu9NyqKV+H8c4
2021/05/17 19:30:37 Decrypt foo
2021/05/17 19:30:37   Public Key: 
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxlGKaAhr0eL/DjhAMsPTDjqD0SwsLyqm0O24j2dREWtQ8KogOE39
VUDFNbccBzJm4TQGSEgzcDJYsfk9UieEWu03Xas2KaU6LvE1z1LiakUUvJ/pgmA/
MElbTGY7nugh6YOlaGhK4JVi+XXrvI7uah8fkOvitIxABpQv+T8kPkC1yLSg0GHe
DPd2GuNcgsfeVCQqC86NPOy5HVCTD2ZA0Y0uREGK/uM3zeWNUdDjQo6wO3Cw7A1C
S8MQ6Xcjhq4T3dJGjFuZVkiP1+6Daj8UKoVLDnMXy28r07IloAEZFTe/QZyadJjC
BGTYVWWBwqy4au/sSW6kaTZnHiXml96aEQIDAQAB
-----END RSA PUBLIC KEY-----

Signing 3 bytes with foo
2021/05/17 19:30:37 Signature vN+te5+tlO6avoDIV50wZZJP2Mj8VO7/9IN+CVljyHAcHijw3hF1itUMgflyycnj1WNNjVFf0WDvSzI7LYslh9BkBw1bdQxBc5L15yzG6UsVNzjrn+JFNpl6LtnVgClEAfBeC6giqZAT1WL/rDm3GHWnOpVYJcTe1MUHHYT2QFGV996aCyBV5TpW8eLr3Jc8vcQhhebLhAlviCvyefLeBEafXvtVD5erErl+DPQAChEjmyJkyVJy6R5xrLtlM7sUydPMygztsQxm3STp3uYu7TDuibl75H4iJ/7dcGSOMP/6pBUBKA4sGDZQpNX9rJIw5DyEiYDk9JMbVgjEZDqAEQ
2021/05/17 19:30:37 >>>>>> Signature Verified
Signing 3 bytes with foo
2021/05/17 19:30:37 Signature vN+te5+tlO6avoDIV50wZZJP2Mj8VO7/9IN+CVljyHAcHijw3hF1itUMgflyycnj1WNNjVFf0WDvSzI7LYslh9BkBw1bdQxBc5L15yzG6UsVNzjrn+JFNpl6LtnVgClEAfBeC6giqZAT1WL/rDm3GHWnOpVYJcTe1MUHHYT2QFGV996aCyBV5TpW8eLr3Jc8vcQhhebLhAlviCvyefLeBEafXvtVD5erErl+DPQAChEjmyJkyVJy6R5xrLtlM7sUydPMygztsQxm3STp3uYu7TDuibl75H4iJ/7dcGSOMP/6pBUBKA4sGDZQpNX9rJIw5DyEiYDk9JMbVgjEZDqAEQ

```

8. Print object to see the new key

```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
```


## Wrapping AES key with RSA key

In this mode, we will do the inverse where we generate and AES key which we will wrap/unwrap with RSA key


see `aes_rsa/import.go`:


1. First create AES key suitable with `CKA_EXTRACTABLE`

```golang
	aesKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true), // we do need to extract this
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, make([]byte, 32)), /* KeyLength */
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "AESKeyToWrap"),   /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
```

2. Use it to encrypt/decrypt some sample data

This is just to test, its not necessary for wrap/unwrap


3. Create RSA key enabled for `CKA_WRAP/CKA_UNWRAP`

```golang
	wpublicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "wrappub1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, wpubID),
	}
	wprivateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "wrappriv1"),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, wprivID),
	}
```

4. Wrap AES key with RSA

```golang
wrappedPrivBytes, err := p.WrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, wpbk, aesKey)
```

5. Unwrap Key with RSA Private Key

```golang
	aesKeyTemplate = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "UnwrappedAESKey"), /* Name of Key */
		pkcs11.NewAttribute(pkcs11.CKA_ID, importedPrivID),
	}

	// B) unwrap AES key using RSA Public Wrapping Key
	ik, err := p.UnwrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, wpvk, wrappedPrivBytes, aesKeyTemplate)
```

6. Print new key

```
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
```


## Importing RSA Cert and Key using pkcs11-tool

```bash
# first convert the PEM cert and KEY to DER
openssl x509 -in sts.crt -out sts.crt.der -outform DER 
openssl rsa -inform pem -in sts.key -outform der -out sts.key.der

# Reset softHSM

cd mtls_pkcs11/misc/softhsm.conf
rm -rf tokens
mkdir tokens
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin


pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot-index=0 --init-token --label="token1" --so-pin="123456"
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --label="token1" --init-pin --so-pin "123456" --pin mynewpin

# import key and cert
pkcs11-tool  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --pin mynewpin \
   --write-object sts.crt.der --type cert --id 10 --label keylabel3 --slot-index 0

pkcs11-tool  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --pin mynewpin \
   --write-object sts.key.der --type privkey --id 10 --label keylabel3 --slot-index 0

# list objects
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --list-token-slots
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so  --list-objects --pin mynewpin
```


### References

- [https://github.com/google/pkcs11test](https://github.com/google/pkcs11test)
- [https://github.com/OpenSC/OpenSC/blob/master/src/tools/pkcs11-tool.c#L3189](https://github.com/OpenSC/OpenSC/blob/master/src/tools/pkcs11-tool.c#L3189)
- [https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-introduce-cloud-hsm#access-cloud-hsm-pkcs11](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-introduce-cloud-hsm#access-cloud-hsm-pkcs11)
- [https://github.com/IBM-Cloud/hpcs-grep11-go/blob/master/examples/server.go](https://github.com/IBM-Cloud/hpcs-grep11-go/blob/master/examples/server.go)
- [https://github.com/letsencrypt/pkcs11key/blob/master/key.go](https://github.com/letsencrypt/pkcs11key/blob/master/key.go)


