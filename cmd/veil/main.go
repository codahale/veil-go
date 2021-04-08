package main

import (
	"encoding/base64"
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

func decodePublicKeys(pathsOrKeys []string) (keys []*veil.PublicKey, err error) {
	keys = make([]*veil.PublicKey, len(pathsOrKeys))

	for i, path := range pathsOrKeys {
		keys[i], err = decodePublicKey(path)
		if err != nil {
			return nil, err
		}
	}

	return
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

func openOutput(path string, armor bool) (io.WriteCloser, error) {
	dst := os.Stdout

	if path != "-" {
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}

		dst = f
	}

	if armor {
		return &base64Encoder{dst: dst, enc: base64.NewEncoder(base64.StdEncoding, dst)}, nil
	}

	return dst, nil
}

func openInput(path string, armor bool) (io.ReadCloser, error) {
	src := os.Stdin

	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		src = f
	}

	if armor {
		return &base64Decoder{src: src, dec: base64.NewDecoder(base64.StdEncoding, src)}, nil
	}

	return src, nil
}

type base64Encoder struct {
	dst io.WriteCloser
	enc io.WriteCloser
}

func (b *base64Encoder) Write(p []byte) (n int, err error) {
	return b.enc.Write(p)
}

func (b *base64Encoder) Close() error {
	if err := b.enc.Close(); err != nil {
		return err
	}

	return b.dst.Close()
}

var _ io.WriteCloser = &base64Encoder{}

type base64Decoder struct {
	src io.ReadCloser
	dec io.Reader
}

func (b *base64Decoder) Read(p []byte) (n int, err error) {
	return b.dec.Read(p)
}

func (b *base64Decoder) Close() error {
	return b.src.Close()
}

var _ io.ReadCloser = &base64Decoder{}
