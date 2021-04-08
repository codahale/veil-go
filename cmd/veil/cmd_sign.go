package main

import (
	"github.com/alecthomas/kong"
)

type signCmd struct {
	SecretKey     string `arg:"" type:"existingfile" help:"The path to the secret key."`
	KeyID         string `arg:"" help:"The ID of the private key to use."`
	Message       string `arg:"" type:"existingfile" help:"The path to the message."`
	SignedMessage string `arg:"" type:"path" help:"The path to the signed message."`

	Armor bool `help:"Encode the signed message as base64."`
}

func (cmd *signCmd) Run(_ *kong.Context) error {
	// Decrypt the secret key.
	sk, err := decryptSecretKey(cmd.SecretKey)
	if err != nil {
		return err
	}

	// Open the message input.
	src, err := openInput(cmd.Message, false)
	if err != nil {
		return err
	}

	defer func() { _ = src.Close() }()

	// Open the signed output.
	dst, err := openOutput(cmd.SignedMessage, cmd.Armor)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Create the signed message.
	_, err = sk.PrivateKey(cmd.KeyID).Sign(dst, src)

	return err
}
