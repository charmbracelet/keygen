package keygen

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestNewKeyPair(t *testing.T) {
	kp, err := New("")
	if err != nil {
		t.Errorf("error creating SSH key pair: %v", err)
	}
	if kp.keyType != Ed25519 {
		t.Errorf("expected default key type to be Ed25519, got %s", kp.keyType)
	}
}

func nilTest(t testing.TB, kp *KeyPair) {
	t.Helper()
	if kp == nil {
		t.Error("expected key pair to be non-nil")
	}
	if kp.PrivateKey() == nil {
		t.Error("expected private key to be non-nil")
	}
	if kp.PublicKey() == nil {
		t.Error("expected public key to be non-nil")
	}
	if kp.RawPrivateKey() == nil {
		t.Error("expected raw private key to be non-nil")
	}
	if kp.RawProtectedPrivateKey() == nil {
		t.Error("expected raw protected private key to be non-nil")
	}
	if kp.AuthorizedKey() == "" {
		t.Error("expected authorized key to be non-nil")
	}
	if kp.Signer() == nil {
		t.Error("expected signer to be non-nil")
	}
}

func TestNilKeyPair(t *testing.T) {
	for _, kt := range []KeyType{RSA, Ed25519, ECDSA} {
		t.Run(fmt.Sprintf("test nil key pair for %s", kt), func(t *testing.T) {
			kp, err := New("", WithKeyType(kt))
			if err != nil {
				t.Errorf("error creating SSH key pair: %v", err)
			}
			nilTest(t, kp)
		})
	}
}

func TestNilKeyPairWithPassphrase(t *testing.T) {
	for _, kt := range []KeyType{RSA, Ed25519, ECDSA} {
		t.Run(fmt.Sprintf("test nil key pair for %s", kt), func(t *testing.T) {
			kp, err := New("", WithKeyType(kt), WithPassphrase("test"))
			if err != nil {
				t.Errorf("error creating SSH key pair: %v", err)
			}
			nilTest(t, kp)
		})
	}
}

func TestNilKeyPairTestdata(t *testing.T) {
	for _, kt := range []KeyType{RSA, Ed25519, ECDSA} {
		t.Run(fmt.Sprintf("test nil key pair for %s", kt), func(t *testing.T) {
			kp, err := New(filepath.Join("testdata", "test_"+kt.String()), WithPassphrase("test"), WithKeyType(kt))
			if err != nil {
				t.Errorf("error creating SSH key pair: %v", err)
			}
			nilTest(t, kp)
		})
	}
}

func TestUnsupportedCurve(t *testing.T) {
	_, err := New("", WithKeyType(ECDSA), WithEllipticCurve(elliptic.P224()))
	if err == nil {
		t.Error("expected error for unsupported curve")
	}
	_, err = New("", WithKeyType(ECDSA), WithEllipticCurve(elliptic.P256()))
	if err != nil {
		t.Errorf("expected no error for supported curve, got %v", err)
	}
}

func TestGenerateEd25519Keys(t *testing.T) {
	// Create temp directory for keys
	dir := t.TempDir()
	filename := "test"

	k := &KeyPair{
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
		if len(k.RawPrivateKey()) == 0 {
			t.Error("error creating SSH private key PEM; key is 0 bytes")
		}
		if len(k.AuthorizedKey()) == 0 {
			t.Error("error creating SSH authorized key; key is 0 bytes")
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

	k := &KeyPair{
		path:    filepath.Join(dir, filename),
		keyType: ECDSA,
		ec:      elliptic.P384(),
	}

	t.Run("test generate SSH keys", func(t *testing.T) {
		err := k.generateECDSAKeys(k.ec)
		if err != nil {
			t.Errorf("error creating SSH key pair: %v", err)
		}

		// TODO: is there a good way to validate these? Lengths seem to vary a bit,
		// so far now we're just asserting that the keys indeed exist.
		if len(k.RawPrivateKey()) == 0 {
			t.Error("error creating SSH private key PEM; key is 0 bytes")
		}
		if len(k.AuthorizedKey()) == 0 {
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
		t.Run("test generate public key with empty dir", func(t *testing.T) {
			fp := filepath.Join(t.TempDir(), "testkey")
			k, err := New(fp, WithKeyType(keyType), WithWrite())
			if err != nil {
				t.Fatalf("error creating SSH key pair: %v", err)
			}
			f, err := os.Open(fp + ".pub")
			if err != nil {
				t.Fatalf("error opening SSH key file: %v", err)
			}
			defer f.Close()
			fc, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("error reading SSH key file: %v", err)
			}
			if bytes.Equal(k.RawAuthorizedKey(), fc) {
				t.Errorf("error key mismatch\nprivate key:\n%s\n\nactual file:\n%s", k.PrivateKey(), string(fc))
			}
			t.Cleanup(func() {
				os.Remove(fp)
				os.Remove(fp + ".pub")
			})
		})
	}
}

func TestGenerateKeyWithPassphrase(t *testing.T) {
	ph := "testpass"
	for _, keyType := range []KeyType{RSA, ECDSA, Ed25519} {
		t.Run("test generate key with passphrase", func(t *testing.T) {
			fp := filepath.Join(t.TempDir(), "testph")
			_, err := New(fp, WithKeyType(keyType), WithPassphrase(ph), WithWrite())
			if err != nil {
				t.Fatalf("error creating SSH key pair: %v", err)
			}
			f, err := os.Open(fp)
			if err != nil {
				t.Fatalf("error opening SSH key file: %v", err)
			}
			defer f.Close()
			fc, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("error reading SSH key file: %v", err)
			}
			k, err := New(fp, WithKeyType(keyType), WithPassphrase(ph))
			if err != nil {
				t.Fatalf("error reading SSH key pair: %v", err)
			}
			if bytes.Equal(k.RawPrivateKey(), fc) {
				t.Errorf("encrypted private key matches file contents")
			}
			t.Cleanup(func() {
				os.Remove(fp)
				os.Remove(fp + ".pub")
			})
		})
	}
}

func TestReadingKeyWithPassphrase(t *testing.T) {
	for _, keyType := range []KeyType{RSA, ECDSA, Ed25519} {
		kp := filepath.Join("testdata", "test")
		_, err := New(kp, WithKeyType(keyType), WithPassphrase("test"))
		if err != nil {
			t.Fatalf("error reading SSH key pair: %v", err)
		}
	}
}

func TestKeynameSuffix(t *testing.T) {
	for _, keyType := range []KeyType{RSA, ECDSA, Ed25519} {
		t.Run("test keyname suffix", func(t *testing.T) {
			fp := filepath.Join(t.TempDir(), "testkey_"+keyType.String())
			_, err := New(fp, WithKeyType(keyType), WithWrite())
			if err != nil {
				t.Fatalf("error creating SSH key pair: %v", err)
			}
			if _, err := os.Stat(fp); os.IsNotExist(err) {
				t.Errorf("private key file %s does not exist", fp)
			}
			t.Cleanup(func() {
				os.Remove(fp)
				os.Remove(fp + ".pub")
			})
		})
	}
}

func TestExpandPath(t *testing.T) {
	tmpdir := t.TempDir()
	os.Setenv("TEMP", tmpdir)
	defer os.Unsetenv("TEMP")

	// Test environment variable expansion
	if fp := expandPath(filepath.Join("$TEMP", "testkey")); fp != filepath.Join(tmpdir, "testkey") {
		t.Errorf("error expanding path: %s", fp)
	}

	// Test tilde expansion
	homedir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("error getting user home directory: %v", err)
	}

	if fp := expandPath(filepath.Join("~", "testkey")); fp != filepath.Join(homedir, "testkey") {
		t.Errorf("error expanding path: %s", fp)
	}
}
