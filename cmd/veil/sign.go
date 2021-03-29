package main

import "github.com/alecthomas/kong"

type signCmd struct {
	SecretKey     string `arg:"" type:"existingfile" help:"The path to the secret key."`
	Message       string `arg:"" type:"existingfile" help:"The path to the message."`
	SignedMessage string `arg:"" type:"path" help:"The path to the signed message."`
}

func (cmd *signCmd) Run(_ *kong.Context) error {
	// Decrypt the secret key.
	sk, err := decryptSecretKey(cmd.SecretKey)
	if err != nil {
		return err
	}

	// Open the message input.
	src, err := openInput(cmd.Message)
	if err != nil {
		return err
	}

	defer func() { _ = src.Close() }()

	// Open the signed output.
	dst, err := openOutput(cmd.SignedMessage)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Create the signed message.
	_, err = sk.Sign(dst, src)

	return err
}
