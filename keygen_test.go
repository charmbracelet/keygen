package keygen

import (
	"crypto/elliptic"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestNewSSHKeyPair(t *testing.T) {
	p := filepath.Join(t.TempDir(), "test")
	_, err := NewWithWrite(p, []byte(""), RSA)
	if err != nil {
		t.Errorf("error creating SSH key pair: %v", err)
	}
}

func TestGenerateEd25519Keys(t *testing.T) {
	// Create temp directory for keys
	dir := t.TempDir()
	filename := "test"

	k := &SSHKeyPair{
		path:    filepath.Join(dir, filename),
		keyType: Ed25519,
	}

	t.Run("test generate SSH keys", func(t *testing.T) {
		err := k.generateEd25519Keys()
		if err != nil {
			t.Errorf("error creating SSH key pair: %v", err)
		}

		// TODO: is there a good way to validate these? Lengths seem to vary a bit,
		// so far now we're just asserting that the keys indeed exist.
		if len(k.PrivateKeyPEM()) == 0 {
			t.Error("error creating SSH private key PEM; key is 0 bytes")
		}
		if len(k.PublicKey()) == 0 {
			t.Error("error creating SSH public key; key is 0 bytes")
		}
	})

	t.Run("test write SSH keys", func(t *testing.T) {
		k.path = filepath.Join(dir, "ssh1", filename)
		if err := k.prepFilesystem(); err != nil {
			t.Errorf("filesystem error: %v\n", err)
		}
		if err := k.WriteKeys(); err != nil {
			t.Errorf("error writing SSH keys to %s: %v", k.path, err)
		}
		if testing.Verbose() {
			t.Logf("Wrote keys to %s", k.path)
		}
	})

	t.Run("test not overwriting existing keys", func(t *testing.T) {
		k.path = filepath.Join(dir, "ssh2", filename)
		if err := k.prepFilesystem(); err != nil {
			t.Errorf("filesystem error: %v\n", err)
		}

		// Private key
		if !createEmptyFile(t, k.privateKeyPath()) {
			return
		}
		if err := k.WriteKeys(); err == nil {
			t.Errorf("we wrote the private key over an existing file, but we were not supposed to")
		}
		if err := os.Remove(k.privateKeyPath()); err != nil {
			t.Errorf("could not remove file %s", k.privateKeyPath())
		}

		// Public key
		if !createEmptyFile(t, k.publicKeyPath()) {
			return
		}
		if err := k.WriteKeys(); err == nil {
			t.Errorf("we wrote the public key over an existing file, but we were not supposed to")
		}
	})
}

func TestGenerateECDSAKeys(t *testing.T) {
	// Create temp directory for keys
	dir := t.TempDir()
	filename := "test"

	k := &SSHKeyPair{
		path:    filepath.Join(dir, filename),
		keyType: ECDSA,
	}

	t.Run("test generate SSH keys", func(t *testing.T) {
		err := k.generateECDSAKeys(elliptic.P384())
		if err != nil {
			t.Errorf("error creating SSH key pair: %v", err)
		}

		// TODO: is there a good way to validate these? Lengths seem to vary a bit,
		// so far now we're just asserting that the keys indeed exist.
		if len(k.PrivateKeyPEM()) == 0 {
			t.Error("error creating SSH private key PEM; key is 0 bytes")
		}
		if len(k.PublicKey()) == 0 {
			t.Error("error creating SSH public key; key is 0 bytes")
		}
	})

	t.Run("test write SSH keys", func(t *testing.T) {
		k.path = filepath.Join(dir, "ssh1", filename)
		if err := k.prepFilesystem(); err != nil {
			t.Errorf("filesystem error: %v\n", err)
		}
		if err := k.WriteKeys(); err != nil {
			t.Errorf("error writing SSH keys to %s: %v", k.path, err)
		}
		if testing.Verbose() {
			t.Logf("Wrote keys to %s", k.path)
		}
	})

	t.Run("test not overwriting existing keys", func(t *testing.T) {
		k.path = filepath.Join(dir, "ssh2", filename)
		if err := k.prepFilesystem(); err != nil {
			t.Errorf("filesystem error: %v\n", err)
		}

		// Private key
		if !createEmptyFile(t, k.privateKeyPath()) {
			return
		}
		if err := k.WriteKeys(); err == nil {
			t.Errorf("we wrote the private key over an existing file, but we were not supposed to")
		}
		if err := os.Remove(k.privateKeyPath()); err != nil {
			t.Errorf("could not remove file %s", k.privateKeyPath())
		}

		// Public key
		if !createEmptyFile(t, k.publicKeyPath()) {
			return
		}
		if err := k.WriteKeys(); err == nil {
			t.Errorf("we wrote the public key over an existing file, but we were not supposed to")
		}
	})
}

// touchTestFile is a utility function we're using in testing.
func createEmptyFile(t *testing.T, path string) (ok bool) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Errorf("could not create directory %s: %v", dir, err)
		return false
	}
	f, err := os.Create(path)
	if err != nil {
		t.Errorf("could not create file %s", path)
		return false
	}
	if err := f.Close(); err != nil {
		t.Errorf("could not close file: %v", err)
		return false
	}
	if testing.Verbose() {
		t.Logf("created dummy file at %s", path)
	}
	return true
}

func TestGeneratePublicKeyWithEmptyDir(t *testing.T) {
	for _, keyType := range []KeyType{RSA, ECDSA, Ed25519} {
		func(t *testing.T) {
			k, err := NewWithWrite("testkey", nil, keyType)
			if err != nil {
				t.Fatalf("error creating SSH key pair: %v", err)
			}
			fn := fmt.Sprintf("testkey_%s", keyType)
			f, err := os.Open(fn + ".pub")
			if err != nil {
				t.Fatalf("error opening SSH key file: %v", err)
			}
			defer f.Close()
			fc, err := ioutil.ReadAll(f)
			if err != nil {
				t.Fatalf("error reading SSH key file: %v", err)
			}
			defer os.Remove(fn)
			defer os.Remove(fn + ".pub")
			if string(k.PublicKey()) != string(fc) {
				t.Errorf("error key mismatch\nprivate key:\n%s\n\nactual file:\n%s", k.PrivateKey(), string(fc))
			}
		}(t)
	}
}

func TestGenerateKeyWithPassphrase(t *testing.T) {
	for _, keyType := range []KeyType{RSA, ECDSA, Ed25519} {
		ph := "testpass"
		func(t *testing.T) {
			_, err := NewWithWrite("testph", []byte(ph), keyType)
			if err != nil {
				t.Fatalf("error creating SSH key pair: %v", err)
			}
			fn := fmt.Sprintf("testph_%s", keyType)
			f, err := os.Open(fn)
			if err != nil {
				t.Fatalf("error opening SSH key file: %v", err)
			}
			defer f.Close()
			fc, err := ioutil.ReadAll(f)
			if err != nil {
				t.Fatalf("error reading SSH key file: %v", err)
			}
			defer os.Remove(fn)
			defer os.Remove(fn + ".pub")
			k, err := New("testph", []byte(ph), keyType)
			if err != nil {
				t.Fatalf("error reading SSH key pair: %v", err)
			}
			if string(k.PrivateKeyPEM()) == string(fc) {
				t.Errorf("encrypted private key matches file contents")
			}
		}(t)
	}
}

func TestReadingKeyWithPassphrase(t *testing.T) {
	for _, keyType := range []KeyType{RSA, ECDSA, Ed25519} {
		kp := filepath.Join("testdata", "test")
		_, err := New(kp, []byte("test"), keyType)
		if err != nil {
			t.Fatalf("error reading SSH key pair: %v", err)
		}
	}
}
