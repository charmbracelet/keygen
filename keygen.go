// Package keygen handles the creation of new SSH key pairs.
package keygen

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/mikesmitty/edkey"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh"
)

// KeyType represents a type of SSH key.
type KeyType string

// Supported key types.
const (
	RSA     KeyType = "rsa"
	Ed25519 KeyType = "ed25519"
)

const rsaDefaultBits = 4096

// ErrMissingSSHKeys indicates we're missing some keys that we expected to
// have after generating. This should be an extreme edge case.
var ErrMissingSSHKeys = errors.New("missing one or more keys; did something happen to them after they were generated?")

// FilesystemErr is used to signal there was a problem creating keys at the
// filesystem-level. For example, when we're unable to create a directory to
// store new SSH keys in.
type FilesystemErr struct {
	Err error
}

// Error returns a human-readable string for the erorr. It implements the error
// interface.
func (e FilesystemErr) Error() string {
	return e.Err.Error()
}

// Unwrap returne the underlying error.
func (e FilesystemErr) Unwrap() error {
	return e.Err
}

// SSHKeysAlreadyExistErr indicates that files already exist at the location at
// which we're attempting to create SSH keys.
type SSHKeysAlreadyExistErr struct {
	Path string
}

// SSHKeyPair holds a pair of SSH keys and associated methods.
type SSHKeyPair struct {
	PrivateKeyPEM []byte
	PublicKey     []byte
	KeyDir        string
	Filename      string // private key filename; public key will have .pub appended
}

func (s SSHKeyPair) privateKeyPath() string {
	return filepath.Join(s.KeyDir, s.Filename)
}

func (s SSHKeyPair) publicKeyPath() string {
	return filepath.Join(s.KeyDir, s.Filename+".pub")
}

// New generates an SSHKeyPair, which contains a pair of SSH keys.
func New(path, name string, passphrase []byte, keyType KeyType) (*SSHKeyPair, error) {
	var err error
	s := &SSHKeyPair{
		KeyDir:   path,
		Filename: fmt.Sprintf("%s_%s", name, keyType),
	}
	if s.IsKeyPairExists() {
		pubData, err := ioutil.ReadFile(s.publicKeyPath())
		if err != nil {
			return nil, err
		}
		s.PublicKey = pubData
		privData, err := ioutil.ReadFile(s.privateKeyPath())
		if err != nil {
			return nil, err
		}
		s.PrivateKeyPEM = privData
		return s, nil
	}
	switch keyType {
	case Ed25519:
		err = s.generateEd25519Keys()
	case RSA:
		err = s.generateRSAKeys(rsaDefaultBits, passphrase)
	default:
		return nil, fmt.Errorf("unsupported key type %s", keyType)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// New generates an SSHKeyPair and writes it to disk if not exist.
func NewWithWrite(path, name string, passphrase []byte, keyType KeyType) (*SSHKeyPair, error) {
	s, err := New(path, name, passphrase, keyType)
	if err != nil {
		return nil, err
	}
	if !s.IsKeyPairExists() {
		if err = s.WriteKeys(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// generateEd25519Keys creates a pair of EdD25519 keys for SSH auth.
func (s *SSHKeyPair) generateEd25519Keys() error {
	// Generate keys
	pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// Encode PEM
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privateKey),
	})

	// Prepare public key
	publicKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return err
	}

	// serialize for public key file on disk
	serializedPublicKey := ssh.MarshalAuthorizedKey(publicKey)

	s.PrivateKeyPEM = pemBlock
	s.PublicKey = pubKeyWithMemo(serializedPublicKey)
	return nil
}

// generateRSAKeys creates a pair for RSA keys for SSH auth.
func (s *SSHKeyPair) generateRSAKeys(bitSize int, passphrase []byte) error {
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

	// Get ASN.1 DER format
	x509Encoded := x509.MarshalPKCS1PrivateKey(privateKey)

	block := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509Encoded,
	}

	// encrypt private key with passphrase
	if len(passphrase) > 0 {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, passphrase, x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	}

	// Private key in PEM format
	pemBlock := pem.EncodeToMemory(block)

	// Generate public key
	publicRSAKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return err
	}

	// serialize for public key file on disk
	serializedPubKey := ssh.MarshalAuthorizedKey(publicRSAKey)

	s.PrivateKeyPEM = pemBlock
	s.PublicKey = pubKeyWithMemo(serializedPubKey)
	return nil
}

// prepFilesystem makes sure the state of the filesystem is as it needs to be
// in order to write our keys to disk. It will create and/or set permissions on
// the SSH directory we're going to write our keys to (for example, ~/.ssh) as
// well as make sure that no files exist at the location in which we're going
// to write out keys.
func (s *SSHKeyPair) prepFilesystem() error {
	var err error

	s.KeyDir, err = homedir.Expand(s.KeyDir)
	if err != nil {
		return err
	}

	info, err := os.Stat(s.KeyDir)
	if os.IsNotExist(err) {
		// Directory doesn't exist: create it
		return os.MkdirAll(s.KeyDir, 0700)
	}
	if err != nil {
		// There was another error statting the directory; something is awry
		return FilesystemErr{Err: err}
	}
	if !info.IsDir() {
		// It exists but it's not a directory
		return FilesystemErr{Err: fmt.Errorf("%s is not a directory", s.KeyDir)}
	}
	if info.Mode().Perm() != 0700 {
		// Permissions are wrong: fix 'em
		if err := os.Chmod(s.KeyDir, 0700); err != nil {
			return FilesystemErr{Err: err}
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
func (s *SSHKeyPair) WriteKeys() error {
	if len(s.PrivateKeyPEM) == 0 || len(s.PublicKey) == 0 {
		return ErrMissingSSHKeys
	}

	if err := s.prepFilesystem(); err != nil {
		return err
	}

	if err := writeKeyToFile(s.PrivateKeyPEM, s.privateKeyPath()); err != nil {
		return err
	}
	if err := writeKeyToFile(s.PublicKey, s.publicKeyPath()); err != nil {
		return err
	}

	return nil
}

func (s *SSHKeyPair) IsKeyPairExists() bool {
	return fileExists(s.privateKeyPath()) && fileExists(s.publicKeyPath())
}

func writeKeyToFile(keyBytes []byte, path string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return ioutil.WriteFile(path, keyBytes, 0600)
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

// attaches a user@host suffix to a serialized public key. returns the original
// pubkey if we can't get the username or host.
func pubKeyWithMemo(pubKey []byte) []byte {
	u, err := user.Current()
	if err != nil {
		return pubKey
	}
	hostname, err := os.Hostname()
	if err != nil {
		return pubKey
	}

	return append(bytes.TrimRight(pubKey, "\n"), []byte(fmt.Sprintf(" %s@%s\n", u.Username, hostname))...)
}

// Error returns the a human-readable error message for SSHKeysAlreadyExistErr.
// It satisfies the error interface.
func (e SSHKeysAlreadyExistErr) Error() string {
	return fmt.Sprintf("ssh key %s already exists", e.Path)
}
