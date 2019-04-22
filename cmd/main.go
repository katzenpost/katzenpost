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
)

func main() {
	cfgFile := flag.String("f", "katzenpost.toml", "Path to the server config file.")
	flag.Parse()

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

	// Load config file.
	cfg, err := config.LoadFile(*cfgFile, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Create a client and connect to the mixnet Provider.
	c, err := client.New(cfg)
	if err != nil {
		panic(err)
	}
	s, err := c.NewSession()
	if err != nil {
		panic(err)
	}

	client, err := catshadow.New(c.GetBackendLog(), c.GetLogger("catshadow"), s)
	if err != nil {
		panic(err)
	}

	// Start up an interactive shell.
	shell := NewShell(client, c.GetLogger("catshadow_shell"))
	shell.Run()
}
