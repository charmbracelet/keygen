# Keygen

[![Latest Release](https://img.shields.io/github/release/charmbracelet/keygen.svg)](https://github.com/charmbracelet/keygen/releases)
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://pkg.go.dev/github.com/charmbracelet/keygen?tab=doc)
[![Build Status](https://github.com/charmbracelet/keygen/workflows/build/badge.svg)](https://github.com/charmbracelet/keygen/actions)
[![Go ReportCard](https://goreportcard.com/badge/charmbracelet/keygen)](https://goreportcard.com/report/charmbracelet/keygen)

An SSH key pair generator. Supports generating RSA and Ed25519 keys.

## Example

```go
k, err := NewSSHKeyPair(".ssh", "my_awesome_key", []byte(""), "ed25519")
if err != nil {
	fmt.Printf("error creating SSH key pair: %v", err)
	os.Exit(1)
}
if !k.KeyPairExist() {
	err = k.WriteKeys()
	if err != nil {
		fmt.Printf("error writing SSH key pair: %v", err)
		os.Exit(1)
	}
}
```

## License

[MIT](https://github.com/charmbracelet/keygen/raw/master/LICENSE)

***

Part of [Charm](https://charm.sh).

<a href="https://charm.sh/"><img alt="the Charm logo" src="https://stuff.charm.sh/charm-badge-unrounded.jpg" width="400"></a>

Charm热爱开源 • Charm loves open source