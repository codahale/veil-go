package main

import (
	"github.com/alecthomas/kong"
)

type signCmd struct {
	SecretKey string `arg:"" type:"existingfile" help:"The path to the secret key."`
	KeyID     string `arg:"" help:"The ID of the private key to use."`
	Message   string `arg:"" type:"existingfile" help:"The path to the message."`
	Output    string `arg:"" type:"path" help:"The path to the signature file."`
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

	// Open the signature output.
	dst, err := openOutput(cmd.Output)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Sign the message.
	sig, err := sk.PrivateKey(cmd.KeyID).Sign(src)
	if err != nil {
		return err
	}

	// Encode the signature.
	sigText, err := sig.MarshalText()
	if err != nil {
		return err
	}

	// Write out the signature.
	_, err = dst.Write(sigText)

	return err
}
