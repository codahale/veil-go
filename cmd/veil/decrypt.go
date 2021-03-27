package main

import (
	"os"

	"github.com/alecthomas/kong"
)

type decryptCmd struct {
	SecretKey  *os.File   `arg:"" help:"The path to the secret key."`
	Ciphertext *os.File   `arg:"" help:"The path to the ciphertext file."`
	Plaintext  string     `arg:"" type:"path" help:"The path to the ciphertext file."`
	Senders    []*os.File `arg:"" repeated:"" help:"The public keys of the possible senders."`
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

	w, err := openOutput(cmd.Plaintext)
	if err != nil {
		return err
	}

	defer func() { _ = w.Close() }()

	_, _, err = sk.Decrypt(w, cmd.Ciphertext, senders)

	return err
}

func openOutput(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdout, nil
	}

	w, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	return w, nil
}
