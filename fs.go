package keygen

import (
	"io/fs"
	"os"
)

// KeyFS is an interface that defines everything we need to read and write
// keys.
type KeyFS interface {
	fs.ReadFileFS
	fs.StatFS
	Chmod(name string, mode fs.FileMode) error
	MkdirAll(path string, perm fs.FileMode) error
	WriteFile(path string, data []byte, perm fs.FileMode) error
}

var _ KeyFS = &RealFS{}

// RealFS is a KeyFS implementation that uses the real filesystem.
type RealFS struct{}

// WriteFile implements KeyFS.
func (n *RealFS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// MkdirAll implements KeyFS.
func (n *RealFS) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(path, perm)
}

// Chmod implements KeyFS.
func (n *RealFS) Chmod(name string, mode fs.FileMode) error {
	return os.Chmod(name, mode)
}

// Open implements KeyFS.
func (n *RealFS) Open(name string) (fs.File, error) {
	return os.Open(name)
}

// ReadFile implements KeyFS.
func (n *RealFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

// Stat implements KeyFS.
func (n *RealFS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(name)
}
