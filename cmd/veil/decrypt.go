package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
)

type decryptCmd struct {
	SecretKey  string   `arg:"" type:"existingfile" help:"The path to the secret key."`
	Ciphertext *os.File `arg:"" help:"The path to the ciphertext file."`
	Plaintext  string   `arg:"" type:"path" help:"The path to the plaintext file."`
	Senders    []string `arg:"" repeated:"" type:"existingfile" help:"The public keys of the possible senders."`
}

func (cmd *decryptCmd) Run(_ *kong.Context) error {
	sk, err := decryptSecretKey(cmd.SecretKey)
	if err != nil {
		return err
	}

	senders, err := parsePublicKeys(cmd.Senders)
	if err != nil {
		return err
	}

	defer func() { _ = cmd.Ciphertext.Close() }()

	f, err := os.Create(cmd.Plaintext)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	sender, _, err := sk.Decrypt(f, cmd.Ciphertext, senders)
	if err != nil {
		_ = f.Close()

		_ = os.Remove(cmd.Plaintext)

		return err
	}

	_, _ = fmt.Fprintf(os.Stderr, "Message originally encrypted by %s\n", sender)

	return nil
}
