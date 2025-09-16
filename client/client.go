package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/ThalesGroup/crypto11"
	"github.com/salrashid123/pkcssigner"
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

	clientCaCert, err := os.ReadFile("ca_scratchpad/ca/root-ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	clientCaCertPool := x509.NewCertPool()
	clientCaCertPool.AppendCertsFromPEM(clientCaCert)

	pubPEMData, err := os.ReadFile("ca_scratchpad/certs/softhsm-client.crt")
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(pubPEMData)
	if err != nil {
		log.Fatal(err)
	}
	filex509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	r, err := pkcssigner.NewPKCSCrypto(&pkcssigner.PKCS{
		Context:         ctx,
		PkcsId:          nil,                 //softhsm
		PkcsLabel:       []byte("keylabel2"), //softhsm
		X509Certificate: filex509,            //softhsm

		// PkcsId:    []byte{1}, //yubikey
		// PkcsLabel: nil,       //yubikey
		// X509Certificate: filex509, //yubikey or omit if PKCS device has cert already

		// PkcsId:         nil,                  //tpm
		// PkcsId: []byte{0}, //tpm
		// // PkcsLabel:      []byte("keylabel1"),  //tpm https://github.com/ThalesIgnite/crypto11/issues/82
		// X509Certificate: filex509, //tpm
	})
	if err != nil {
		log.Fatal(err)
	}

	tcert, err := r.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      clientCaCertPool,
			ServerName:   "server.domain.com",
			Certificates: []tls.Certificate{tcert},
		},
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
