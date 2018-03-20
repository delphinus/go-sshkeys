package sshkeys

// SSHKeys is the struct to use create keys
type SSHKeys struct {
	PrivateKey []byte
	PublicKey  []byte

	filename   string
	keyType    string
	keyLength  int
	dir        string
	passphrase []byte
	comment    []byte
}

// Option is an interface to set options for SSHKeys.
type Option interface {
	apply(*SSHKeys)
}

// WithFilename is an option to specify the filename of keys.  The default
// value is `id_rsa` and the public key will be `id_rsa.pub`.
func WithFilename(n string) Option { return &withFilenameOption{n} }

type withFilenameOption struct{ filename string }

func (o *withFilenameOption) apply(s *SSHKeys) {
	if o.filename != "" {
		s.filename = o.filename
	}
}

// WithKeyType is an option to specify the type of keys.  Now this package
// supports RSA keys only.
func WithKeyType(t string) Option {
	// TODO: do not ignore t and support other types.
	return &withKeyTypeOption{"RSA"}
}

type withKeyTypeOption struct{ keyType string }

func (o *withKeyTypeOption) apply(s *SSHKeys) { s.keyType = o.keyType }

// WithKeyLength is an option to specify the length of keys.
func WithKeyLength(l int) Option {
	if l < 0 {
		l = 0
	}
	return &withKeyLengthOption{l}
}

type withKeyLengthOption struct{ length int }

func (o *withKeyLengthOption) apply(s *SSHKeys) { s.keyLength = o.length }

// WithDir is an option to specify the directory to store created keys.  It
// will create the dir before saving keys if not exists.
func WithDir(d string) Option {
	if d == "" {
		d = "."
	}
	return &withDirOption{d}
}

type withDirOption struct{ dir string }

func (o *withDirOption) apply(s *SSHKeys) { s.dir = o.dir }

// WithPassphrase is an option to specify the pass phrase to encrypt keys.
func WithPassphrase(pp []byte) Option { return &withPassphraseOption{pp} }

type withPassphraseOption struct{ passphrase []byte }

func (o *withPassphraseOption) apply(s *SSHKeys) { s.passphrase = o.passphrase }

// WithComment is an option to specify the comment of the public key file.
// This is usually used to store the mail address.
func WithComment(c []byte) Option { return &withCommentOption{c} }

type withCommentOption struct{ comment []byte }

func (o *withCommentOption) apply(s *SSHKeys) { s.comment = o.comment }
