package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ThalesIgnite/crypto11"
	salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"
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

	r, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
		Context:        ctx,
		PkcsId:         nil,                                      //softhsm
		PkcsLabel:      []byte("keylabel1"),                      //softhsm
		PublicCertFile: "ca_scratchpad/certs/softhsm-server.crt", //softhsm

		// PkcsId:         []byte{1},                  //yubikey
		// PkcsLabel:      nil,                        //yubikey
		// PublicCertFile: "certs/yubikey-server.crt", //yubikey

		// PkcsId: []byte{0}, //tpm
		// // PkcsLabel:      []byte("keylabel1"),  //tpm https://github.com/ThalesIgnite/crypto11/issues/82
		// PublicCertFile: "certs/tpm-server.crt", //tpm
	})
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
			Certificates: []tls.Certificate{r.TLSCertificate()},
		},
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")
	log.Fatalf("Unable to start Server %v", err)

}
