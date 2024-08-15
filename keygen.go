// Package keygen handles the creation of new SSH key pairs.
package keygen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyType represents a type of SSH key.
type KeyType string

// Supported key types.
const (
	RSA     KeyType = "rsa"
	Ed25519 KeyType = "ed25519"
	ECDSA   KeyType = "ecdsa"
)

// String implements the Stringer interface for KeyType.
func (k KeyType) String() string {
	return string(k)
}

const rsaDefaultBits = 4096

// ErrMissingSSHKeys indicates we're missing some keys that we expected to
// have after generating. This should be an extreme edge case.
var ErrMissingSSHKeys = errors.New("missing one or more keys; did something happen to them after they were generated?")

// ErrUnsupportedKeyType indicates an unsupported key type.
type ErrUnsupportedKeyType struct {
	keyType string
	ecName  string
}

// Error implements the error interface for ErrUnsupportedKeyType.
func (e ErrUnsupportedKeyType) Error() string {
	err := "unsupported key type"
	if e.keyType != "" {
		err += fmt.Sprintf(": %s", e.keyType)
	}
	if e.ecName != "" {
		err += fmt.Sprintf(" (ECDSA curve: %s)", e.ecName)
	}
	return err
}

// FilesystemErr is used to signal there was a problem creating keys at the
// filesystem-level. For example, when we're unable to create a directory to
// store new SSH keys in.
type FilesystemErr struct {
	Err error
}

// Error returns a human-readable string for the error. It implements the error
// interface.
func (e FilesystemErr) Error() string {
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e FilesystemErr) Unwrap() error {
	return e.Err
}

// SSHKeysAlreadyExistErr indicates that files already exist at the location at
// which we're attempting to create SSH keys.
type SSHKeysAlreadyExistErr struct {
	Path string
}

// SSHKeyPair holds a pair of SSH keys and associated methods.
// Deprecated: Use KeyPair instead.
type SSHKeyPair = KeyPair

// KeyPair holds a pair of SSH keys and associated methods.
type KeyPair struct {
	path       string // private key filename path; public key will have .pub appended
	writeKeys  bool
	passphrase []byte
	rsaBitSize int
	ec         elliptic.Curve
	keyType    KeyType
	privateKey crypto.PrivateKey
}

func (s KeyPair) privateKeyPath() string {
	return s.path
}

func (s KeyPair) publicKeyPath() string {
	return s.privateKeyPath() + ".pub"
}

// Option is a functional option for KeyPair.
type Option func(*KeyPair)

// WithPassphrase sets the passphrase for the private key.
func WithPassphrase(passphrase string) Option {
	return func(s *KeyPair) {
		s.passphrase = []byte(passphrase)
	}
}

// WithKeyType sets the key type for the key pair.
// Available key types are RSA, Ed25519, and ECDSA.
func WithKeyType(keyType KeyType) Option {
	return func(s *KeyPair) {
		s.keyType = keyType
	}
}

// WithBitSize sets the key size for the RSA key pair.
// This option is ignored for other key types.
func WithBitSize(bits int) Option {
	return func(s *KeyPair) {
		s.rsaBitSize = bits
	}
}

// WithWrite writes the key pair to disk if it doesn't exist.
func WithWrite() Option {
	return func(s *KeyPair) {
		s.writeKeys = true
	}
}

// WithEllipticCurve sets the elliptic curve for the ECDSA key pair.
// Supported curves are P-256, P-384, and P-521.
// The default curve is P-384.
// This option is ignored for other key types.
func WithEllipticCurve(curve elliptic.Curve) Option {
	return func(s *KeyPair) {
		s.ec = curve
	}
}

// New generates a KeyPair, which contains a pair of SSH keys.
//
// If the key pair already exists, it will be loaded from disk, otherwise, a
// new SSH key pair is generated.
// If no key type is specified, Ed25519 will be used.
func New(path string, opts ...Option) (*KeyPair, error) {
	var err error
	s := &KeyPair{
		path:       expandPath(path),
		rsaBitSize: rsaDefaultBits,
		ec:         elliptic.P384(),
		keyType:    Ed25519,
	}

	for _, opt := range opts {
		opt(s)
	}

	ecName := s.ec.Params().Name
	switch ecName {
	case "P-256", "P-384", "P-521":
	default:
		return nil, ErrUnsupportedKeyType{keyType: ecName, ecName: ecName}
	}

	if s.KeyPairExists() {
		privData, err := os.ReadFile(s.privateKeyPath())
		if err != nil {
			return nil, err
		}

		var k interface{}
		if len(s.passphrase) > 0 {
			k, err = ssh.ParseRawPrivateKeyWithPassphrase(privData, s.passphrase)
		} else {
			k, err = ssh.ParseRawPrivateKey(privData)
		}

		if err != nil {
			return nil, err
		}

		switch k := k.(type) {
		case *rsa.PrivateKey:
			s.keyType = RSA
			s.privateKey = k
		case *ecdsa.PrivateKey:
			s.keyType = ECDSA
			s.privateKey = k
		case *ed25519.PrivateKey:
			s.keyType = Ed25519
			s.privateKey = k
		default:
			return nil, ErrUnsupportedKeyType{keyType: fmt.Sprintf("%T", k)}
		}

		return s, nil
	}

	switch s.keyType {
	case Ed25519:
		err = s.generateEd25519Keys()
	case RSA:
		err = s.generateRSAKeys(s.rsaBitSize)
	case ECDSA:
		err = s.generateECDSAKeys(s.ec)
	default:
		return nil, ErrUnsupportedKeyType{keyType: string(s.keyType)}
	}

	if err != nil {
		return nil, err
	}

	if s.writeKeys {
		return s, s.WriteKeys()
	}

	return s, nil
}

// PrivateKey returns the unencrypted crypto.PrivateKey.
func (s *KeyPair) PrivateKey() crypto.PrivateKey {
	switch s.keyType {
	case RSA, Ed25519, ECDSA:
		return s.privateKey
	default:
		return nil
	}
}

// Ensure that KeyPair implements crypto.Signer.
// This is used to ensure that the private key is a valid crypto.Signer to be
// passed to ssh.NewSignerFromKey.
var (
	_ crypto.Signer = (*rsa.PrivateKey)(nil)
	_ crypto.Signer = (*ecdsa.PrivateKey)(nil)
	_ crypto.Signer = (*ed25519.PrivateKey)(nil)
)

// Signer returns an ssh.Signer for the key pair.
func (s *KeyPair) Signer() ssh.Signer {
	sk, _ := ssh.NewSignerFromKey(s.PrivateKey())
	return sk
}

// PublicKey returns the ssh.PublicKey for the key pair.
func (s *KeyPair) PublicKey() ssh.PublicKey {
	p, _ := ssh.NewPublicKey(s.cryptoPublicKey())
	return p
}

func (s *KeyPair) cryptoPublicKey() crypto.PublicKey {
	switch s.keyType {
	case RSA:
		key, ok := s.privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil
		}
		return key.Public()
	case Ed25519:
		key, ok := s.privateKey.(*ed25519.PrivateKey)
		if !ok {
			return nil
		}
		return key.Public()
	case ECDSA:
		key, ok := s.privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil
		}
		return key.Public()
	default:
		return nil
	}
}

// CryptoPublicKey returns the crypto.PublicKey of the SSH key pair.
func (s *KeyPair) CryptoPublicKey() crypto.PublicKey {
	return s.cryptoPublicKey()
}

// RawAuthorizedKey returns the underlying SSH public key (RFC 4253) in OpenSSH
// authorized_keys format.
func (s *KeyPair) RawAuthorizedKey() []byte {
	bts, err := os.ReadFile(s.publicKeyPath())
	if err != nil {
		return []byte(s.AuthorizedKey())
	}

	_, c, opts, _, err := ssh.ParseAuthorizedKey(bts)
	if err != nil {
		return []byte(s.AuthorizedKey())
	}

	ak := s.authorizedKey(s.PublicKey())
	if len(opts) > 0 {
		ak = fmt.Sprintf("%s %s", strings.Join(opts, ","), ak)
	}

	if c != "" {
		ak = fmt.Sprintf("%s %s", ak, c)
	}

	return []byte(ak)
}

func (s *KeyPair) authorizedKey(pk ssh.PublicKey) string {
	if pk == nil {
		return ""
	}

	// serialize authorized key
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

// AuthorizedKey returns the SSH public key (RFC 4253) in OpenSSH authorized_keys
// format. The returned string is trimmed of sshd options and comments.
func (s *KeyPair) AuthorizedKey() string {
	return s.authorizedKey(s.PublicKey())
}

// RawPrivateKey returns the raw unencrypted private key bytes in PEM format.
func (s *KeyPair) RawPrivateKey() []byte {
	return s.rawPrivateKey(nil)
}

// RawProtectedPrivateKey returns the raw password protected private key bytes
// in PEM format.
func (s *KeyPair) RawProtectedPrivateKey() []byte {
	return s.rawPrivateKey(s.passphrase)
}

func (s *KeyPair) rawPrivateKey(pass []byte) []byte {
	block, err := s.pemBlock(pass)
	if err != nil {
		return nil
	}

	return pem.EncodeToMemory(block)
}

func (s *KeyPair) pemBlock(passphrase []byte) (*pem.Block, error) {
	key := s.PrivateKey()
	if key == nil {
		return nil, ErrMissingSSHKeys
	}
	switch s.keyType {
	case RSA, Ed25519, ECDSA:
		if len(passphrase) > 0 {
			return ssh.MarshalPrivateKeyWithPassphrase(key, "", passphrase)
		}
		return ssh.MarshalPrivateKey(key, "")
	default:
		return nil, ErrUnsupportedKeyType{keyType: s.keyType.String()}
	}
}

// generateEd25519Keys creates a pair of EdD25519 keys for SSH auth.
func (s *KeyPair) generateEd25519Keys() error {
	// Generate keys
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.privateKey = &privateKey

	return nil
}

// generateEd25519Keys creates a pair of EdD25519 keys for SSH auth.
func (s *KeyPair) generateECDSAKeys(curve elliptic.Curve) error {
	// Generate keys
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	s.privateKey = privateKey
	return nil
}

// generateRSAKeys creates a pair for RSA keys for SSH auth.
func (s *KeyPair) generateRSAKeys(bitSize int) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return err
	}
	// Validate private key
	err = privateKey.Validate()
	if err != nil {
		return err
	}
	s.privateKey = privateKey
	return nil
}

// prepFilesystem makes sure the state of the filesystem is as it needs to be
// in order to write our keys to disk. It will create and/or set permissions on
// the SSH directory we're going to write our keys to (for example, ~/.ssh) as
// well as make sure that no files exist at the location in which we're going
// to write out keys.
func (s *KeyPair) prepFilesystem() error {
	var err error

	keyDir := filepath.Dir(s.path)
	if keyDir != "" {
		keyDir, err = filepath.Abs(keyDir)
		if err != nil {
			return err
		}

		info, err := os.Stat(keyDir)
		if os.IsNotExist(err) {
			// Directory doesn't exist: create it
			return os.MkdirAll(keyDir, 0o700)
		}
		if err != nil {
			// There was another error statting the directory; something is awry
			return FilesystemErr{Err: err}
		}
		if !info.IsDir() {
			// It exists but it's not a directory
			return FilesystemErr{Err: fmt.Errorf("%s is not a directory", keyDir)}
		}
		if info.Mode().Perm() != 0o700 {
			// Permissions are wrong: fix 'em
			if err := os.Chmod(keyDir, 0o700); err != nil {
				return FilesystemErr{Err: err}
			}
		}
	}

	// Make sure the files we're going to write to don't already exist
	if fileExists(s.privateKeyPath()) {
		return SSHKeysAlreadyExistErr{Path: s.privateKeyPath()}
	}
	if fileExists(s.publicKeyPath()) {
		return SSHKeysAlreadyExistErr{Path: s.publicKeyPath()}
	}

	// The directory looks good as-is
	return nil
}

// WriteKeys writes the SSH key pair to disk.
func (s *KeyPair) WriteKeys() error {
	var err error
	priv := s.RawProtectedPrivateKey()
	if priv == nil {
		return ErrMissingSSHKeys
	}

	if err = s.prepFilesystem(); err != nil {
		return err
	}

	if err := writeKeyToFile(priv, s.privateKeyPath()); err != nil {
		return err
	}

	ak := s.AuthorizedKey()
	if memo := pubKeyMemo(); memo != "" {
		ak = fmt.Sprintf("%s %s", ak, memo)
	}

	return writeKeyToFile([]byte(ak), s.publicKeyPath())
}

// KeyPairExists checks if the SSH key pair exists on disk.
func (s *KeyPair) KeyPairExists() bool {
	return fileExists(s.privateKeyPath())
}

func writeKeyToFile(keyBytes []byte, path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.WriteFile(path, keyBytes, 0o600)
	}
	return FilesystemErr{Err: fmt.Errorf("file %s already exists", path)}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return false
	}
	return true
}

// expandPath resolves the tilde `~` and any environment variables in path.
func expandPath(path string) string {
	if len(path) > 0 && path[0] == '~' {
		userdir, err := os.UserHomeDir()
		if err != nil {
			return path
		}

		path = filepath.Join(userdir, path[1:])
	}

	return os.ExpandEnv(path)
}

// attaches a user@host suffix to a serialized public key. returns the original
// pubkey if we can't get the username or host.
func pubKeyMemo() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%s@%s\n", u.Username, hostname)
}

// Error returns the a human-readable error message for SSHKeysAlreadyExistErr.
// It satisfies the error interface.
func (e SSHKeysAlreadyExistErr) Error() string {
	return fmt.Sprintf("ssh key %s already exists", e.Path)
}
