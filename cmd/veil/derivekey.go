package main

import (
	"io"

	"github.com/alecthomas/kong"
)

type deriveKeyCmd struct {
	PublicKey string `arg:"" help:"The path to the public key."`
	SubKeyID  string `arg:"" help:"The sub-key ID."`
	Output    string `arg:"" type:"path" default:"-" help:"The output path for the public key."`
}

func (cmd *deriveKeyCmd) Run(_ *kong.Context) error {
	// Decode the public key.
	pk, err := decodePublicKey(cmd.PublicKey)
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
	_, err = io.WriteString(dst, pk.Derive(cmd.SubKeyID).String())

	return err
}
