package main

import (
	"os"

	"github.com/alecthomas/kong"
)

type decryptCmd struct {
	SecretKey  string `arg:"" type:"existingfile" help:"The path to the secret key."`
	KeyID      string `arg:"" help:"The ID of the private key to use."`
	Ciphertext string `arg:"" type:"existingfile" help:"The path to the ciphertext file."`
	Plaintext  string `arg:"" type:"path" help:"The path to the plaintext file."`
	Sender     string `arg:"" repeated:"" help:"The public keys of the sender."`
}

func (cmd *decryptCmd) Run(_ *kong.Context) error {
	// Decrypt the secret key.
	sk, err := decryptSecretKey(cmd.SecretKey)
	if err != nil {
		return err
	}

	// Decode the public key of the sender.
	sender, err := decodePublicKey(cmd.Sender)
	if err != nil {
		return err
	}

	// Open the ciphertext input.
	src, err := os.Open(cmd.Ciphertext)
	if err != nil {
		return err
	}

	defer func() { _ = src.Close() }()

	// Open the plaintext output.
	dst, err := openOutput(cmd.Plaintext)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Decrypt the ciphertext.
	_, err = sk.PrivateKey(cmd.KeyID).Decrypt(dst, src, sender)

	return err
}
