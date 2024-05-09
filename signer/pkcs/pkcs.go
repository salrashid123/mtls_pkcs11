package pkcs

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/ThalesIgnite/crypto11"
)

const ()

var (
	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
	clientCAs       *x509.CertPool
	clientAuth      *tls.ClientAuthType
	pkcsContext     *crypto11.Context
)

type PKCS struct {
	priv         crypto.Signer
	ExtTLSConfig *tls.Config

	PublicCertFile string
	pcert          *x509.Certificate
	PkcsId         []byte
	PkcsLabel      []byte
	Context        *crypto11.Context

	refreshMutex *sync.Mutex
}

func NewPKCSCrypto(conf *PKCS) (PKCS, error) {
	pkcsContext = conf.Context

	if conf.ExtTLSConfig != nil {
		if len(conf.ExtTLSConfig.Certificates) > 0 {
			return PKCS{}, fmt.Errorf("Certificates value in ExtTLSConfig Ignored")
		}

		if len(conf.ExtTLSConfig.CipherSuites) > 0 {
			return PKCS{}, fmt.Errorf("CipherSuites value in ExtTLSConfig Ignored")
		}
	}
	var err error
	conf.priv, err = conf.Context.FindKeyPair(conf.PkcsId, conf.PkcsLabel)
	if err != nil {
		return PKCS{}, fmt.Errorf("Could not init Crypto.signer")
	}

	if conf.priv == nil {
		return PKCS{}, fmt.Errorf("Could not find KeyPair")
	}

	if conf.PublicCertFile == "" {
		crt, err := conf.Context.FindCertificate(conf.PkcsId, conf.PkcsLabel, nil)
		if err != nil {
			return PKCS{}, fmt.Errorf("Could not retrieve x509 Certificate from PKCS config;  please specify PublicCertFile")
		}
		// if crt == nil {
		// 	return PKCS{}, fmt.Errorf("Could not retrieve x509 Certificate from PKCS config;  please specify PublicCertFile")
		// }
		conf.pcert = crt
	} else {
		pubPEM, err := os.ReadFile(conf.PublicCertFile)
		if err != nil {
			return PKCS{}, fmt.Errorf("Unable to read keys %v", err)
		}
		block, _ := pem.Decode([]byte(pubPEM))
		if block == nil {
			return PKCS{}, fmt.Errorf("failed to parse PEM block containing the public key")
		}
		conf.pcert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return PKCS{}, fmt.Errorf("failed to parse public key: " + err.Error())
		}

	}

	return PKCS{
		refreshMutex: &sync.Mutex{}, // guards impersonatedToken; held while fetching or updating it.
		priv:         conf.priv,
		ExtTLSConfig: conf.ExtTLSConfig,
		pcert:        conf.pcert,
		PkcsId:       conf.PkcsId,
		PkcsLabel:    conf.PkcsLabel,
		Context:      conf.Context,
	}, nil

}

func (t PKCS) Public() crypto.PublicKey {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()
	return t.priv.Public()
}

func (t PKCS) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()
	return t.priv.Sign(rand, digest, opts)
}

func (t PKCS) TLSCertificate() tls.Certificate {

	x509Certificate = *t.pcert
	var privKey crypto.PrivateKey = t

	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        &x509Certificate,
		Certificate: [][]byte{x509Certificate.Raw},
	}
}

func (t PKCS) TLSConfig() *tls.Config {

	return &tls.Config{
		Certificates: []tls.Certificate{t.TLSCertificate()},

		RootCAs:      t.ExtTLSConfig.RootCAs,
		ClientCAs:    t.ExtTLSConfig.ClientCAs,
		ClientAuth:   t.ExtTLSConfig.ClientAuth,
		ServerName:   t.ExtTLSConfig.ServerName,
		CipherSuites: t.ExtTLSConfig.CipherSuites,
		MaxVersion:   t.ExtTLSConfig.MaxVersion,
		MinVersion:   t.ExtTLSConfig.MinVersion,
	}
}
