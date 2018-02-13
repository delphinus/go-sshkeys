package sshKeys

import "os"

func Example() {
	s := New(
		WithFilename("foo_id_rsa"),
		WithDir(os.Getenv("HOME")+"/.foo-ssh"),
		WithPassphrase([]byte("some passphrase")),
		WithComment([]byte("someone@example.com")),
	)
	_ = s.Generate()
	_ = s.Save()

	// it will generate keys on files:
	// ~/.foo-ssh/foo_id_rsa, ~/.foo-ssh/foo_id_rsa.pub
}
