package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/ThalesIgnite/crypto11"
	salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"
)

var ()

const ()

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	fmt.Fprint(w, "ok")
}

func main() {
	// var slotNum *int
	// slotNum = new(int)
	// *slotNum = 0

	// softhsm
	// export SOFTHSM2_CONF=/home/srashid/Desktop/misc/soft_hsm/softhsm.conf
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

	clientCaCert, err := ioutil.ReadFile("ca_scratchpad/ca/root-ca.crt")
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	r, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
		Context:        ctx,
		PkcsId:         nil,                                      //softhsm
		PkcsLabel:      []byte("keylabel1"),                      //softhsm
		PublicCertFile: "ca_scratchpad/certs/softhsm-client.crt", //softhsm

		// PkcsId:    []byte{1}, //yubikey
		// PkcsLabel: nil,       //yubikey
		// PublicCertFile: "certs/yubikey-client.crt", //yubikey or omit if PKCS device has cert already

		// PkcsId:         nil,                  //tpm
		// PkcsId: []byte{0}, //tpm
		// // PkcsLabel:      []byte("keylabel1"),  //tpm https://github.com/ThalesIgnite/crypto11/issues/82
		// PublicCertFile: "certs/tpm-client.crt", //tpm

		ExtTLSConfig: &tls.Config{
			RootCAs:    clientCaCertPool,
			ServerName: "pkcs.domain.com",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	tr := &http.Transport{
		TLSClientConfig: r.TLSConfig(),
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://localhost:8081")
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))

}
