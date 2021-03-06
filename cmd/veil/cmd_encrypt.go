package main

import (
	"github.com/alecthomas/kong"
)

type encryptCmd struct {
	SecretKey  string   `arg:"" type:"existingfile" help:"The path to the secret key."`
	KeyID      string   `arg:"" help:"The ID of the private key to use."`
	Plaintext  string   `arg:"" type:"existingfile" help:"The path to the plaintext file."`
	Ciphertext string   `arg:"" type:"path" help:"The path to the ciphertext file."`
	Recipients []string `arg:"" repeated:"" help:"The public keys of the recipients."`

	Fakes   int `help:"The number of fake recipients to add."`
	Padding int `help:"The number of bytes of random padding to add."`
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
	_, err = sk.PrivateKey(cmd.KeyID).Encrypt(dst, src, recipients, cmd.Fakes, cmd.Padding)

	return err
}
