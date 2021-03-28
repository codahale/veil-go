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
	pwd, err := askPassword("Enter password: ")
	if err != nil {
		return err
	}

	cfm, err := askPassword("Confirm password: ")
	if err != nil {
		return err
	}

	if !bytes.Equal(pwd, cfm) {
		return errPasswordMismatch
	}

	sk, err := veil.NewSecretKey()
	if err != nil {
		return err
	}

	esk, err := veil.EncryptSecretKey(sk, pwd, nil)
	if err != nil {
		return err
	}

	if err := os.WriteFile(cmd.SecretKey, esk, 0600); err != nil {
		return err
	}

	return os.WriteFile(cmd.PublicKey, sk.PublicKey(), 0600)
}

var errPasswordMismatch = errors.New("password mismatch")
