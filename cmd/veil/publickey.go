package main

import (
	"io"

	"github.com/alecthomas/kong"
)

type publicKeyCmd struct {
	SecretKey string `arg:"" type:"existingfile" help:"The path to the secret key."`
	Output    string `arg:"" type:"path" default:"-" help:"The output path for the encrypted secret key."`

	Path string `help:"The derivation path."`
}

func (cmd *publicKeyCmd) Run(_ *kong.Context) error {
	// Decrypt the secret key.
	sk, err := decryptSecretKey(cmd.SecretKey)
	if err != nil {
		return err
	}

	// Open the output.
	dst, err := openOutput(cmd.Output)
	if err != nil {
		return err
	}

	defer func() { _ = dst.Close() }()

	// Derive the public key, encode it, and write it to the output.
	_, err = io.WriteString(dst, sk.PublicKey(cmd.Path).String())

	return err
}
