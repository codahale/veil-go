package main

import (
	"bytes"
	"errors"
	"os"

	"github.com/alecthomas/kong"
	"github.com/codahale/veil"
)

type generateCmd struct {
	SecretKey string `arg:"" type:"path" help:"The output path for the encrypted secret key."`
	PublicKey string `arg:"" type:"path" help:"The output path for the public key."`
}

func (cmd *generateCmd) Run(_ *kong.Context) error {
	passphrase, err := askPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}

	confirmation, err := askPassphrase("Confirm passphrase: ")
	if err != nil {
		return err
	}

	if !bytes.Equal(passphrase, confirmation) {
		return errPassphraseMismatch
	}

	sk, err := veil.NewSecretKey()
	if err != nil {
		return err
	}

	esk, err := veil.EncryptSecretKey(sk, passphrase, nil)
	if err != nil {
		return err
	}

	if err := os.WriteFile(cmd.SecretKey, esk, 0600); err != nil {
		return err
	}

	return os.WriteFile(cmd.PublicKey, sk.PublicKey(), 0600)
}

var errPassphraseMismatch = errors.New("passphrase mismatch")
