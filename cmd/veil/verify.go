package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/codahale/veil"
)

type verifyCmd struct {
	PublicKey string `arg:"" type:"existingfile" help:"The path to the public key."`
	Message   string `arg:"" type:"existingfile" help:"The path to the message."`
	Signature string `arg:"" type:"existingfile" help:"The path to the signature file."`
}

func (cmd *verifyCmd) Run(_ *kong.Context) error {
	// Open and decode the public key.
	pk, err := parsePublicKey(cmd.PublicKey)
	if err != nil {
		return err
	}

	// Open the message input.
	src, err := openInput(cmd.Message)
	if err != nil {
		return err
	}

	defer func() { _ = src.Close() }()

	// Read the signature.
	text, err := os.ReadFile(cmd.Signature)
	if err != nil {
		return err
	}

	// Decode the signature.
	var sig veil.Signature
	if err := sig.UnmarshalText(text); err != nil {
		return err
	}

	// Verify the signature.
	return pk.Verify(src, sig)
}
