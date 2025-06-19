// SPDX-FileCopyrightText: Copyright (C) 2025  David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikepem "github.com/katzenpost/hpqc/nike/pem"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	writingKeypairFormat = "Writing keypair to %s and %s\n"
	errBothKeysExist     = "both keys already exist"
	errOneKeyExists      = "one of the keys already exists"
)

func main() {
	keyType := flag.String("type", "kem", "type is either: nike, kem or sign")
	schemeName := flag.String("scheme", "x25519", "name of the nike, kem or sign scheme")
	outName := flag.String("out", "out", "output keypair name")
	flag.Parse()

	if *keyType == "" {
		panic("type cannot be empty")
	}
	if *schemeName == "" {
		panic("scheme cannot be empty")
	}
	if *outName == "" {
		panic("out cannot be empty")
	}

	switch {
	case *keyType == "kem":
		pubout := fmt.Sprintf("%s.kem_public.pem", *outName)
		privout := fmt.Sprintf("%s.kem_private.pem", *outName)
		fmt.Printf(writingKeypairFormat, pubout, privout)

		switch {
		case utils.BothExists(privout, pubout):
			panic(errBothKeysExist)
		case utils.BothNotExists(privout, pubout):
			break
		default:
			panic(errOneKeyExists)
		}

		scheme := kemschemes.ByName(*schemeName)
		pubkey, privkey, err := scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		err = kempem.PublicKeyToFile(pubout, pubkey)
		if err != nil {
			panic(err)
		}
		err = kempem.PrivateKeyToFile(privout, privkey)
		if err != nil {
			panic(err)
		}
	case *keyType == "nike":
		pubout := fmt.Sprintf("%s.nike_public.pem", *outName)
		privout := fmt.Sprintf("%s.nike_private.pem", *outName)
		fmt.Printf(writingKeypairFormat, pubout, privout)

		switch {
		case utils.BothExists(privout, pubout):
			panic(errBothKeysExist)
		case utils.BothNotExists(privout, pubout):
			break
		default:
			panic(errOneKeyExists)
		}

		scheme := nikeschemes.ByName(*schemeName)
		pubkey, privkey, err := scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		err = nikepem.PublicKeyToFile(pubout, pubkey, scheme)
		if err != nil {
			panic(err)
		}
		err = nikepem.PrivateKeyToFile(privout, privkey, scheme)
		if err != nil {
			panic(err)
		}
	case *keyType == "sign":
		pubout := fmt.Sprintf("%s.sign_public.pem", *outName)
		privout := fmt.Sprintf("%s.sign_private.pem", *outName)
		fmt.Printf(writingKeypairFormat, pubout, privout)

		switch {
		case utils.BothExists(privout, pubout):
			panic(errBothKeysExist)
		case utils.BothNotExists(privout, pubout):
			break
		default:
			panic(errOneKeyExists)
		}

		scheme := signschemes.ByName(*schemeName)
		pubkey, privkey, err := scheme.GenerateKey()
		if err != nil {
			panic(err)
		}
		err = signpem.PublicKeyToFile(pubout, pubkey)
		if err != nil {
			panic(err)
		}
		err = signpem.PrivateKeyToFile(privout, privkey)
		if err != nil {
			panic(err)
		}
	default:
		panic("key type must be kem, nike or sign")
	}
}
