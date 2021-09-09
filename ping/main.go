// main.go - Katzenpost ping tool
// Copyright (C) 2018, 2019  David Stainton
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
	"time"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

func randUser() string {
	user := [32]byte{}
	_, err := rand.Reader.Read(user[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", user[:])
}

func main() {
	var configFile string
	var service string
	var count int
	var printDiff bool
	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.StringVar(&service, "s", "", "service name")
	flag.IntVar(&count, "n", 5, "count")
	flag.BoolVar(&printDiff, "printDiff", false, "print payload contents if reply is different than original")
	flag.Parse()

	if service == "" {
		panic("must specify service name with -s")
	}

	cfg, err := config.LoadFile(configFile)
	if err != nil {
		panic(err)
	}
	cfg, linkKey := register(cfg)

	// create a client and connect to the mixnet Provider
	c, err := client.New(cfg)
	if err != nil {
		panic(err)
	}
	session, err := c.NewSession(linkKey)
	if err != nil {
		panic(err)
	}

	serviceDesc, err := session.GetService(service)
	if err != nil {
		panic(err)
	}

	sequentialPing(session, serviceDesc, count, printDiff)

	c.Shutdown()
}
