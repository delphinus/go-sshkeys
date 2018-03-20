package sshkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

const (
	rsaBlockType = "RSA PRIVATE KEY"
)

// New creates a new instance for SSHKeys
func New(opts ...Option) *SSHKeys {
	s := SSHKeys{
		filename:  "id_rsa",
		keyType:   "RSA",
		keyLength: 2048,
		dir:       ".",
	}
	for _, o := range opts {
		o.apply(&s)
	}
	return &s
}

// Generate generates the key pair of RSA.
func (s *SSHKeys) Generate() error {
	pKey, err := rsa.GenerateKey(rand.Reader, s.keyLength)
	if err != nil {
		return fmt.Errorf("error in GenerateKey: %v", err)
	}
	b := &pem.Block{
		Type:  s.blockType(),
		Bytes: x509.MarshalPKCS1PrivateKey(pKey),
	}
	if len(s.passphrase) > 0 {
		b, err = x509.EncryptPEMBlock(
			rand.Reader, b.Type, b.Bytes, s.passphrase, x509.PEMCipherAES256)
		if err != nil {
			return fmt.Errorf("error in EncryptPEMBlock: %v", err)
		}
	}
	pubKey, err := ssh.NewPublicKey(&pKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error in NewPublicKey: %v", err)
	}
	s.PrivateKey = pem.EncodeToMemory(b)
	s.PublicKey = ssh.MarshalAuthorizedKey(pubKey)
	if len(s.comment) > 0 {
		s.PublicKey[len(s.PublicKey)-1] = ' ' // replace the last byte '\n' to a space
		s.PublicKey = append(s.PublicKey, s.comment...)
		s.PublicKey = append(s.PublicKey, '\n')
	}
	return nil
}

// Save saves keys to the supplied dir
func (s *SSHKeys) Save() error {
	if i, err := os.Stat(s.dir); os.IsNotExist(err) || !i.IsDir() {
		if err := os.MkdirAll(s.dir, 0700); err != nil {
			return fmt.Errorf("error in MkdirAll: %v", err)
		}
	}
	if err := ioutil.WriteFile(
		s.privateKeyFile(), s.PrivateKey, 0600); err != nil {
		return fmt.Errorf("error in WriteFile: %v", err)
	}
	if err := ioutil.WriteFile(s.publicKeyFile(), s.PublicKey, 0600); err != nil {
		return fmt.Errorf("error in WriteFile: %v", err)
	}
	return nil
}

// Read reads keys from the supplied dir
func (s *SSHKeys) Read() (err error) {
	s.PrivateKey, err = ioutil.ReadFile(s.privateKeyFile())
	if err != nil {
		return fmt.Errorf("error in ReadFile: %v", err)
	}
	b, _ := pem.Decode(s.PrivateKey)
	if b == nil {
		return errors.New("invalid private key file")
	}
	if len(s.passphrase) > 0 {
		if _, err := x509.DecryptPEMBlock(b, s.passphrase); err != nil {
			return fmt.Errorf("error in DecryptPEMBlock: %v", err)
		}
	}
	s.PublicKey, err = ioutil.ReadFile(s.publicKeyFile())
	if err != nil {
		return fmt.Errorf("error in ReadFile: %v", err)
	}
	return nil
}

func (s *SSHKeys) privateKeyFile() string {
	// TODO: detect keyType and support other than RSA.
	return filepath.Join(s.dir, s.filename)
}

func (s *SSHKeys) publicKeyFile() string {
	// TODO: detect keyType and support other than RSA.
	return filepath.Join(s.dir, s.filename+".pub")
}

func (s *SSHKeys) blockType() string {
	// TODO: detect keyType and support other than RSA.
	return rsaBlockType
}
