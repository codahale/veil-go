package main

import (
	"github.com/alecthomas/kong"
)

type signCmd struct {
	SecretKey string `arg:"" type:"existingfile" help:"The path to the secret key."`
	Message   string `arg:"" type:"existingfile" help:"The path to the message."`
	Signature string `arg:"" type:"path" help:"The path to the signature file."`
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
	dst, err := openOutput(cmd.Signature)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Sign the message.
	sig, err := sk.Sign(src)
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