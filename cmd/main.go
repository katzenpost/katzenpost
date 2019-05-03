// main.go - main function of client
// Copyright (C) 2019  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/katzenpost/catshadow"
	"github.com/katzenpost/client"
	"github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	generate := flag.Bool("g", false, "Generate the state file and then run client.")
	cfgFile := flag.String("f", "katzenpost.toml", "Path to the client config file.")
	stateFile := flag.String("s", "catshadow_statefile", "The catshadow state file path.")
	flag.Parse()

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

	fmt.Println("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	// Load config file.
	cfg, err := config.LoadFile(*cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Decrypt and load the state file.
	fmt.Print("Enter statefile decryption passphrase: ")
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	fmt.Print("\n")

	var stateWorker *catshadow.StateWriter = nil
	var state *catshadow.State = nil
	var catShadowClient *catshadow.Client = nil
	c, err := client.New(cfg)
	if err != nil {
		panic(err)
	}
	if *generate {
		if _, err := os.Stat(*stateFile); !os.IsNotExist(err) {
			panic("cannot generate state file, already exists")
		}
		linkKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		fmt.Println("registering client with mixnet Provider")
		err = client.RegisterClient(cfg, linkKey.PublicKey())
		if err != nil {
			panic(err)
		}
		stateWorker, err = catshadow.NewStateWriter(c.GetLogger("catshadow_state"), *stateFile, passphrase)
		if err != nil {
			panic(err)
		}
		fmt.Println("creating remote message receiver spool")
		catShadowClient, err = catshadow.NewClientAndRemoteSpool(c.GetBackendLog(), c, stateWorker, linkKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("catshadow client successfully created")
	} else {
		stateWorker, state, err = catshadow.LoadStateWriter(c.GetLogger("catshadow_state"), *stateFile, passphrase)
		if err != nil {
			panic(err)
		}
		catShadowClient, err = catshadow.New(c.GetBackendLog(), c, stateWorker, state)
		if err != nil {
			panic(err)
		}
	}
	stateWorker.Start()
	fmt.Println("state worker started")
	catShadowClient.Start()
	fmt.Println("catshadow worker started")
	fmt.Println("starting shell")
	shell := NewShell(catShadowClient, c.GetLogger("catshadow_shell"))
	shell.Run()
}
