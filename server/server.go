package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ThalesGroup/crypto11"
	"github.com/salrashid123/pkcssigner"
	"golang.org/x/net/http2"
)

var ()

const ()

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cn := strings.ToLower(r.TLS.PeerCertificates[0].Subject.CommonName)
		log.Printf("Peer Certificate CN: %s\n", cn)
	}
	fmt.Fprint(w, "ok")
}

func main() {

	// softhsm
	// cd misc/
	// export SOFTHSM2_CONF=`pwd`/softhsm.conf
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

	pubPEMData, err := os.ReadFile("ca_scratchpad/certs/softhsm-server.crt")
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
		PkcsLabel:       []byte("keylabel1"), //softhsm
		X509Certificate: filex509,            //softhsm

		// PkcsId:         []byte{1},                  //yubikey
		// PkcsLabel:      nil,                        //yubikey
		// X509Certificate: filex509, //yubikey

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
	http.HandleFunc("/", fronthandler)

	var server *http.Server
	server = &http.Server{
		Addr: ":8081",
		TLSConfig: &tls.Config{
			RootCAs:      clientCaCertPool,
			ClientCAs:    clientCaCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{tcert},
		},
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")
	log.Fatalf("Unable to start Server %v", err)

}
