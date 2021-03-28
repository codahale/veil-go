package main

import (
	"bytes"
	"errors"

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

	psk, err := veil.NewEncryptedSecretKey(sk, pwd, nil)
	if err != nil {
		return err
	}

	skF, err := openOutput(cmd.SecretKey)
	if err != nil {
		return err
	}

	defer func() { _ = skF.Close() }()

	b, _ := psk.MarshalBinary()

	_, err = skF.Write(b)
	if err != nil {
		return err
	}

	pkF, err := openOutput(cmd.PublicKey)
	if err != nil {
		return err
	}

	defer func() { _ = pkF.Close() }()

	_, err = pkF.Write(sk.PublicKey())

	return err
}

var errPasswordMismatch = errors.New("password mismatch")
