package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/codahale/veil/pkg/veil"
)

type secretKeyCmd struct {
	Output string `arg:"" type:"path" help:"The output path for the encrypted secret key."`
}

func (cmd *secretKeyCmd) Run(_ *kong.Context) error {
	// Prompt for the PBE passphrase.
	passphrase, err := askPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}

	// Generate a new secret key.
	sk, err := veil.NewSecretKey()
	if err != nil {
		return err
	}

	// Encrypt the secret key with the passphrase.
	esk, err := sk.Encrypt(passphrase, nil)
	if err != nil {
		return err
	}

	// Write out the encrypted secret key.
	return os.WriteFile(cmd.Output, esk, 0600)
}
