package main

import (
	"github.com/alecthomas/kong"
	"github.com/codahale/veil"
)

type encryptCmd struct {
	SecretKey  string   `arg:"" type:"existingfile" help:"The path to the secret key."`
	Plaintext  string   `arg:"" type:"existingfile" help:"The path to the plaintext file."`
	Ciphertext string   `arg:"" type:"path" help:"The path to the ciphertext file."`
	Recipients []string `arg:"" repeated:"" help:"The public keys of the recipients."`

	Label   string `help:"The derivation label of the public key shared with the recipients."`
	Fakes   int    `help:"The number of fake recipients to add."`
	Padding int    `help:"The number of bytes of random padding to add."`
}

func (cmd *encryptCmd) Run(_ *kong.Context) error {
	// Decrypt the secret key.
	sk, err := decryptSecretKey(cmd.SecretKey)
	if err != nil {
		return err
	}

	// Decode the recipients' public keys.
	recipients, err := decodePublicKeys(cmd.Recipients)
	if err != nil {
		return err
	}

	// Add fakes, if requested.
	if cmd.Fakes > 0 {
		recipients, err = veil.AddFakes(recipients, cmd.Fakes)
		if err != nil {
			return err
		}
	}

	// Open the plaintext input.
	src, err := openInput(cmd.Plaintext)
	if err != nil {
		return err
	}

	defer func() { _ = src.Close() }()

	// Open the ciphertext output.
	dst, err := openOutput(cmd.Ciphertext)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Encrypt the plaintext.
	_, err = sk.Encrypt(dst, src, recipients, cmd.Label, cmd.Padding)

	return err
}
