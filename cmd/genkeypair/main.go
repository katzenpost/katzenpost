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

func validateArgs(keyType, schemeName, outName string) {
	if keyType == "" {
		panic("type cannot be empty")
	}
	if schemeName == "" {
		panic("scheme cannot be empty")
	}
	if outName == "" {
		panic("out cannot be empty")
	}
}

func checkKeyFilesExist(privout, pubout string) {
	fmt.Printf(writingKeypairFormat, pubout, privout)

	switch {
	case utils.BothExists(privout, pubout):
		panic(errBothKeysExist)
	case utils.BothNotExists(privout, pubout):
		return
	default:
		panic(errOneKeyExists)
	}
}

func generateKemKeypair(schemeName, outName string) {
	pubout := fmt.Sprintf("%s.kem_public.pem", outName)
	privout := fmt.Sprintf("%s.kem_private.pem", outName)

	checkKeyFilesExist(privout, pubout)

	scheme := kemschemes.ByName(schemeName)
	pubkey, privkey, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	if err := kempem.PublicKeyToFile(pubout, pubkey); err != nil {
		panic(err)
	}
	if err := kempem.PrivateKeyToFile(privout, privkey); err != nil {
		panic(err)
	}
}

func generateNikeKeypair(schemeName, outName string) {
	pubout := fmt.Sprintf("%s.nike_public.pem", outName)
	privout := fmt.Sprintf("%s.nike_private.pem", outName)

	checkKeyFilesExist(privout, pubout)

	scheme := nikeschemes.ByName(schemeName)
	pubkey, privkey, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	if err := nikepem.PublicKeyToFile(pubout, pubkey, scheme); err != nil {
		panic(err)
	}
	if err := nikepem.PrivateKeyToFile(privout, privkey, scheme); err != nil {
		panic(err)
	}
}

func generateSignKeypair(schemeName, outName string) {
	pubout := fmt.Sprintf("%s.sign_public.pem", outName)
	privout := fmt.Sprintf("%s.sign_private.pem", outName)

	checkKeyFilesExist(privout, pubout)

	scheme := signschemes.ByName(schemeName)
	pubkey, privkey, err := scheme.GenerateKey()
	if err != nil {
		panic(err)
	}

	if err := signpem.PublicKeyToFile(pubout, pubkey); err != nil {
		panic(err)
	}
	if err := signpem.PrivateKeyToFile(privout, privkey); err != nil {
		panic(err)
	}
}

func main() {
	keyType := flag.String("type", "kem", "type is either: nike, kem or sign")
	schemeName := flag.String("scheme", "x25519", "name of the nike, kem or sign scheme")
	outName := flag.String("out", "out", "output keypair name")
	flag.Parse()

	validateArgs(*keyType, *schemeName, *outName)

	switch *keyType {
	case "kem":
		generateKemKeypair(*schemeName, *outName)
	case "nike":
		generateNikeKeypair(*schemeName, *outName)
	case "sign":
		generateSignKeypair(*schemeName, *outName)
	default:
		panic("key type must be kem, nike or sign")
	}
}
