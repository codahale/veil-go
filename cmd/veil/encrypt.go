package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/codahale/veil"
)

type encryptCmd struct {
	SecretKey  *os.File   `arg:"" help:"The path to the secret key."`
	Plaintext  *os.File   `arg:"" help:"The path to the plaintext file."`
	Ciphertext string     `arg:"" type:"path" help:"The path to the ciphertext file."`
	Recipients []*os.File `arg:"" repeated:"" help:"The public keys of the recipients."`

	Fakes   int `help:"The number of fake recipients to add."`
	Padding int `help:"The number of bytes of random padding to add."`
}

func (cmd *encryptCmd) Run(_ *kong.Context) error {
	sk, err := decryptSecretKey(cmd.SecretKey)
	if err != nil {
		return err
	}

	recipients, err := parsePublicKeys(cmd.Recipients)
	if err != nil {
		return err
	}

	if cmd.Fakes > 0 {
		recipients, err = veil.AddFakes(recipients, cmd.Fakes)
		if err != nil {
			return err
		}
	}

	w, err := openOutput(cmd.Ciphertext)
	if err != nil {
		return err
	}

	defer func() { _ = w.Close() }()

	_, err = sk.Encrypt(w, cmd.Plaintext, recipients, cmd.Padding)

	return err
}
