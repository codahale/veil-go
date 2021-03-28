package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/codahale/veil"
	"golang.org/x/term"
)

type cli struct {
	Generate generateCmd `cmd:"" help:"Generate a new key pair."`
	Encrypt  encryptCmd  `cmd:"" help:"Encrypt a message for a set of recipients."`
	Decrypt  decryptCmd  `cmd:"" help:"Decrypt a message."`
}

func main() {
	var cli cli

	ctx := kong.Parse(&cli)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

func parsePublicKeys(paths []string) ([]veil.PublicKey, error) {
	keys := make([]veil.PublicKey, len(paths))

	for i, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		keys[i] = b
	}

	return keys, nil
}

func decryptSecretKey(path string) (veil.SecretKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pwd, err := askPassphrase("Enter passphrase: ")
	if err != nil {
		return nil, err
	}

	return veil.DecryptSecretKey(b, pwd)
}

func askPassphrase(prompt string) ([]byte, error) {
	defer func() { _, _ = fmt.Fprintln(os.Stderr) }()

	_, _ = fmt.Fprint(os.Stderr, prompt)

	//nolint:unconvert // actually needed
	//goland:noinspection GoRedundantConversion
	return term.ReadPassword(int(syscall.Stdin))
}
