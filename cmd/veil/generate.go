package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/codahale/veil"
)

type generateCmd struct {
	SecretKey string `arg:"" type:"path" help:"The output path for the encrypted secret key."`
	PublicKey string `arg:"" type:"path" help:"The output path for the public key."`
}

func (cmd *generateCmd) Run(_ *kong.Context) error {
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
	esk, err := veil.EncryptSecretKey(sk, passphrase, nil)
	if err != nil {
		return err
	}

	// Write out the encrypted secret key.
	if err := os.WriteFile(cmd.SecretKey, esk, 0600); err != nil {
		return err
	}

	// Write out the public key.
	return os.WriteFile(cmd.PublicKey, []byte(sk.PublicKey()), 0600)
}
