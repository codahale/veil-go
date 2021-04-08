package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"github.com/codahale/veil/pkg/veil/armor"
)

type decryptCmd struct {
	SecretKey  string   `arg:"" type:"existingfile" help:"The path to the secret key."`
	KeyID      string   `arg:"" help:"The ID of the private key to use."`
	Ciphertext string   `arg:"" type:"existingfile" help:"The path to the ciphertext file."`
	Plaintext  string   `arg:"" type:"path" help:"The path to the plaintext file."`
	Senders    []string `arg:"" repeated:"" help:"The public keys of the possible senders."`

	Armor bool `help:"Decode the ciphertext as base64."`
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

	// De-armor the input, if requested.
	if cmd.Armor {
		src = armor.NewDecoder(src)
	}

	// Open the plaintext output.
	dst, err := openOutput(cmd.Plaintext)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Decrypt the ciphertext.
	sender, _, err := sk.PrivateKey(cmd.KeyID).Decrypt(dst, src, senders)
	if err != nil {
		return err
	}

	// Print the verified sender.
	_, _ = fmt.Fprintf(os.Stderr, "Message originally encrypted by %s\n", sender)

	return nil
}
