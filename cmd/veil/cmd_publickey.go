package main

import (
	"io"

	"github.com/alecthomas/kong"
)

type publicKeyCmd struct {
	SecretKey string `arg:"" type:"existingfile" help:"The path to the secret key."`
	KeyID     string `arg:"" help:"The ID of the public key to generate."`
	Output    string `arg:"" type:"path" default:"-" help:"The output path for the public key."`
}

func (cmd *publicKeyCmd) Run(_ *kong.Context) error {
	// Decrypt the secret key.
	sk, err := decryptSecretKey(cmd.SecretKey)
	if err != nil {
		return err
	}

	// Open the output.
	dst, err := openOutput(cmd.Output, false)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Derive the public key, encode it, and write it to the output.
	_, err = io.WriteString(dst, sk.PublicKey(cmd.KeyID).String())

	return err
}
