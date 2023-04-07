# Keygen

[![Latest Release](https://img.shields.io/github/release/charmbracelet/keygen.svg)](https://github.com/charmbracelet/keygen/releases)
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://pkg.go.dev/github.com/charmbracelet/keygen?tab=doc)
[![Build Status](https://github.com/charmbracelet/keygen/workflows/build/badge.svg)](https://github.com/charmbracelet/keygen/actions)
[![Go ReportCard](https://goreportcard.com/badge/charmbracelet/keygen)](https://goreportcard.com/report/charmbracelet/keygen)

An SSH key pair generator with password protected keys support. Supports generating RSA, ECDSA, and Ed25519 keys.

## Example

```go
kp, err := keygen.New("awesome", keygen.WithPassphrase("awesome_secret"),
	keygen.WithKeyType(keygen.Ed25519))
if err != nil {
	log.Fatalf("error creating SSH key pair: %v", err)
}
fmt.Printf("Your authorized key: %s\n", kp.AuthorizedKey())
```

## Feedback

We’d love to hear your thoughts on this project. Feel free to drop us a note!

- [Twitter](https://twitter.com/charmcli)
- [The Fediverse](https://mastodon.social/@charmcli)
- [Discord](https://charm.sh/chat)

## License

[MIT](https://github.com/charmbracelet/keygen/raw/master/LICENSE)

---

Part of [Charm](https://charm.sh).

<a href="https://charm.sh/"><img alt="The Charm logo" src="https://stuff.charm.sh/charm-badge.jpg" width="400"></a>

Charm热爱开源 • Charm loves open source
