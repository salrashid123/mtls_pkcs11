package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ThalesIgnite/crypto11"
)

var (
	servercsrfile = flag.String("servercsrfile", "ca_scratchpad/certs/softhsm-server.csr", "Arbitrary config file")
	clientcsrfile = flag.String("clientcsrfile", "ca_scratchpad/certs/softhsm-client.csr", "Arbitrary config file")
)

const ()

func main() {
	flag.Parse()

	// var slotNum *int
	// slotNum = new(int)
	// *slotNum = 0

	// softhsm
	// export SOFTHSM2_CONF=/absolute/path/to/softhsm.conf
	config := &crypto11.Config{
		Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		TokenLabel: "token1",
		Pin:        "mynewpin",
	}

	// yubikey
	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	// 	TokenLabel: "user1_esodemoapp2_com",
	// 	Pin:        "123456",
	// }

	// tpm
	// config := &crypto11.Config{
	// 	Path:       "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so.1",
	// 	TokenLabel: "token1",
	// 	Pin:        "mynewpin",
	// }

	ctx, err := crypto11.Configure(config)
	if err != nil {
		log.Fatal(err)
	}

	defer ctx.Close()

	// softhsm
	priv, err := ctx.FindKeyPair(nil, []byte("keylabel1"))
	if err != nil {
		log.Fatal(err)
	}

	// yubikey
	// keyID := []byte{1}
	// priv, err := ctx.FindKeyPair(keyID, nil) //
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// tpm
	//keyID := []byte{0}
	// priv, err := ctx.FindKeyPair(keyID, nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// **************************

	// cert, err := ctx.FindCertificate(keyID, nil, nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// if cert != nil {
	// 	log.Printf("Found Certificate with issuer %s ", cert.Issuer)
	// }

	// **************************
	/// SIGN and Verify

	plaintext := []byte("fooo")
	h := sha256.New()
	_, err = h.Write(plaintext)
	if err != nil {
		log.Fatal(err)
	}
	plaintextHash := h.Sum([]byte{})

	sig, err := priv.Sign(rand.Reader, plaintextHash, crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}
	rsaPubkey := priv.Public().(crypto.PublicKey).(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(rsaPubkey, crypto.SHA256, plaintextHash, sig)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Signature Verified")

	// **************************
	/// Generate CSR
	var csrtemplate = x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject: pkix.Name{
			Organization:       []string{"Google"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         "pkcs.domain.com",
		},
		DNSNames: []string{"pkcs.domain.com"},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, priv)
	if err != nil {
		log.Fatalf("Failed to create CSR: %s", err)
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		},
	)
	log.Printf("CSR \n%s\n", string(pemdata))

	f1, err := os.Create(*servercsrfile)
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = f1.WriteString(string(pemdata))
	if err != nil {
		fmt.Println(err)
		f1.Close()
		return
	}
	defer f1.Close()
	f2, err := os.Create(*clientcsrfile)
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = f2.WriteString(string(pemdata))
	if err != nil {
		fmt.Println(err)
		f2.Close()
		return
	}
	defer f2.Close()
}
