package main

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/codahale/veil"
	"golang.org/x/term"
)

type cli struct {
	GenerateKey genKeyCmd  `cmd:"" help:"Generate a new key pair."`
	Encrypt     encryptCmd `cmd:"" help:"Encrypt a message for a set of recipients."`
	Decrypt     decryptCmd `cmd:"" help:"Decrypt a message."`
}

func main() {
	var cli cli

	ctx := kong.Parse(&cli)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

func parsePublicKeys(paths []*os.File) ([]veil.PublicKey, error) {
	keys := make([]veil.PublicKey, len(paths))

	for i, f := range paths {
		b, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}

		keys[i] = b

		if err := f.Close(); err != nil {
			return nil, err
		}
	}

	return keys, nil
}

func decryptSecretKey(f *os.File) (veil.SecretKey, error) {
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	if err := f.Close(); err != nil {
		return nil, err
	}

	var esk veil.EncryptedSecretKey
	if err := esk.UnmarshalBinary(b); err != nil {
		return nil, err
	}

	pwd, err := askPassword("Enter password: ")
	if err != nil {
		return nil, err
	}

	return esk.Decrypt(pwd)
}

func askPassword(prompt string) ([]byte, error) {
	defer func() { _, _ = fmt.Fprintln(os.Stderr) }()

	_, _ = fmt.Fprint(os.Stderr, prompt)

	//nolint:unconvert // actually needed
	//goland:noinspection GoRedundantConversion
	return term.ReadPassword(int(syscall.Stdin))
}
