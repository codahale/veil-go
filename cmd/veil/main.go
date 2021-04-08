package main

import (
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/codahale/veil/pkg/veil"
	"golang.org/x/term"
)

type cli struct {
	SecretKey      secretKeyCmd      `cmd:"" help:"Generate a new secret key."`
	PublicKey      publicKeyCmd      `cmd:"" help:"Derive a public key from a secret key."`
	DeriveKey      deriveKeyCmd      `cmd:"" help:"Derive a public key from another public key."`
	Encrypt        encryptCmd        `cmd:"" help:"Encrypt a message for a set of recipients."`
	Decrypt        decryptCmd        `cmd:"" help:"Decrypt a message."`
	Sign           signCmd           `cmd:"" help:"Create a signed message."`
	SignDetached   signDetachedCmd   `cmd:"" help:"Create a detached signature for a message."`
	Verify         verifyCmd         `cmd:"" help:"Verify a signed message."`
	VerifyDetached verifyDetachedCmd `cmd:"" help:"Verify a detached signature for a message."`
}

func main() {
	var cli cli

	ctx := kong.Parse(&cli)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

func decodePublicKeys(pathsOrKeys []string) ([]*veil.PublicKey, error) {
	keys := make([]*veil.PublicKey, len(pathsOrKeys))

	for i, path := range pathsOrKeys {
		pk, err := decodePublicKey(path)
		if err != nil {
			return nil, err
		}

		keys[i] = pk
	}

	return keys, nil
}

func decodePublicKey(pathOrKey string) (*veil.PublicKey, error) {
	// Try decoding the key directly.
	var pk veil.PublicKey
	if err := pk.UnmarshalText([]byte(pathOrKey)); err == nil {
		return &pk, nil
	}

	// Otherwise, try reading the contents of it as a file.
	b, err := os.ReadFile(pathOrKey)
	if err != nil {
		return nil, err
	}

	// Decode the public key.
	if err := pk.UnmarshalText(b); err != nil {
		return nil, err
	}

	return &pk, nil
}

func decryptSecretKey(path string) (*veil.SecretKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pwd, err := askPassphrase("Enter passphrase: ")
	if err != nil {
		return nil, err
	}

	return veil.DecryptSecretKey(pwd, b)
}

func askPassphrase(prompt string) ([]byte, error) {
	defer func() { _, _ = fmt.Fprintln(os.Stderr) }()

	_, _ = fmt.Fprint(os.Stderr, prompt)

	return term.ReadPassword(int(os.Stdin.Fd()))
}

func openOutput(path string) (io.WriteCloser, error) {
	if path == "-" {
		return os.Stdout, nil
	}

	return os.Create(path)
}

func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return os.Stdin, nil
	}

	return os.Open(path)
}
