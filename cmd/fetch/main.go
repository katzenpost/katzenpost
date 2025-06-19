// main.go - Katzenpost
// Copyright (C) 2017  Yawning Angel.
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
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func main() {
	cfgFile := flag.String("f", "katzenpost-authority.toml", "Path to the authority config file.")
	retry := flag.Int("r", 10, "Number of times to retry")
	delay := flag.Int("d", 30, "Seconds to wait between retries")

	flag.Parse()

	var err error
	cfg, err := config.LoadFile(*cfgFile)
	if err != nil {
		log.Fatal(err)
	}
	cc, err := client.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	var session *client.Session
	retries := 0
	for session == nil {
		session, err = cc.NewTOFUSession(context.Background())
		switch err {
		case nil:
		case pki.ErrNoDocument:
			_, _, till := epochtime.Now()
			<-time.After(till)
		default:
			if retries == *retry {
				log.Fatal(errors.New("Failed to connect within retry limit"))
			}
			<-time.After(time.Duration(*delay) * time.Second)
		}
		retries += 1
	}
	session.WaitForDocument(context.Background())
	doc := session.CurrentDocument()
	if doc != nil {
		// XXX: prettyprint
		fmt.Printf("%v", doc)
	}
}
