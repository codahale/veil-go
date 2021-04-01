package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
)

type decryptCmd struct {
	SecretKey  string   `arg:"" type:"existingfile" help:"The path to the secret key."`
	Ciphertext string   `arg:"" type:"existingfile" help:"The path to the ciphertext file."`
	Plaintext  string   `arg:"" type:"path" help:"The path to the plaintext file."`
	Senders    []string `arg:"" repeated:"" help:"The public keys of the possible senders."`

	Path string `help:"The derivation path of the public key with which the message was encrypted."`
}

func (cmd *decryptCmd) Run(_ *kong.Context) error {
	// Decrypt the secret key.
	sk, err := decryptSecretKey(cmd.SecretKey)
	if err != nil {
		return err
	}

	// Decode the public keys of the possible senders.
	senders, err := decodePublicKeys(cmd.Senders)
	if err != nil {
		return err
	}

	// Open the ciphertext input.
	src, err := openInput(cmd.Ciphertext)
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
	sender, _, err := sk.Decrypt(dst, src, senders, cmd.Path)
	if err != nil {
		return err
	}

	// Print the verified sender.
	_, _ = fmt.Fprintf(os.Stderr, "Message originally encrypted by %s\n", sender)

	return nil
}
