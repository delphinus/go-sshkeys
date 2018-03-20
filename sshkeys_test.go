package sshKeys

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	passphrase = []byte("hogefugao")
	mail       = []byte("hoge@example.com")
)

func TestNew(t *testing.T) {
	a := assert.New(t)
	s := New(
		WithKeyType("RSA"),
		WithKeyLength(2048),
		WithDir("hoge/fuga/hogefuga"),
		WithPassphrase(passphrase),
		WithComment(mail),
	)
	a.Equal("RSA", s.keyType)
	a.Equal(2048, s.keyLength)
	a.Equal("hoge/fuga/hogefuga", s.dir)
	a.Equal(passphrase, s.passphrase)
	a.Equal(mail, s.comment)
}

func TestGenerate(t *testing.T) {
	a := assert.New(t)
	s := New(WithPassphrase([]byte("hogefugahoge")))
	a.NoError(s.Generate())
	dump(t, s)
}

func TestSave(t *testing.T) {
	a := assert.New(t)
	d, err := ioutil.TempDir("", "")
	a.NoError(err)
	defer func() { a.NoError(os.RemoveAll(d)) }()
	s := New(
		WithDir(d),
		WithFilename("hogehogeo"),
	)
	a.NoError(s.Generate())
	a.NoError(s.Save())
	a.Equal(filepath.Join(d, "hogehogeo"), s.privateKeyFile())
	a.Equal(filepath.Join(d, "hogehogeo.pub"), s.publicKeyFile())
	dump(t, s)
}

func TestRead(t *testing.T) {
	a := assert.New(t)
	d, err := ioutil.TempDir("", "")
	a.NoError(err)
	defer func() { a.NoError(os.RemoveAll(d)) }()
	var private, public []byte
	{
		s := New(
			WithDir(d),
			WithPassphrase(passphrase),
			WithComment(mail),
		)
		a.NoError(s.Generate())
		a.NoError(s.Save())
		dump(t, s)
		private = make([]byte, len(s.PrivateKey))
		public = make([]byte, len(s.PublicKey))
		a.Equal(len(s.PrivateKey), copy(private, s.PrivateKey))
		a.Equal(len(s.PublicKey), copy(public, s.PublicKey))
	}
	{
		s := New(
			WithDir(d),
			WithPassphrase(passphrase),
			WithComment(mail),
		)
		a.NoError(s.Read())
		a.Equal(private, s.PrivateKey)
		a.Equal(public, s.PublicKey)
		dump(t, s)
	}
}

// dump is for testing
func dump(t *testing.T, s *SSHKeys) {
	t.Logf("PrivateKey: %s", s.PrivateKey)
	t.Logf("PublicKey: %s", s.PublicKey)
}
