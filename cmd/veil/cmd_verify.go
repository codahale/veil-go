package main

import (
	"github.com/alecthomas/kong"
	"github.com/codahale/veil/pkg/veil/armor"
)

type verifyCmd struct {
	PublicKey     string `arg:"" help:"The signer's public key."`
	SignedMessage string `arg:"" type:"existingfile" help:"The path to the signed message."`
	Message       string `arg:"" type:"path" help:"The path to the message."`

	Armor bool `help:"Decode the signed message as base64."`
}

func (cmd *verifyCmd) Run(_ *kong.Context) error {
	// Open and decode the public key.
	pk, err := decodePublicKey(cmd.PublicKey)
	if err != nil {
		return err
	}

	// Open the signed message input.
	src, err := openInput(cmd.SignedMessage)
	if err != nil {
		return err
	}

	defer func() { _ = src.Close() }()

	// De-armor the input, if requested.
	if cmd.Armor {
		src = armor.NewDecoder(src)
	}

	// Open the verified output.
	dst, err := openOutput(cmd.Message)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Verify the message.
	_, err = pk.Verify(dst, src)

	return err
}
