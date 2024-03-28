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
	mrand "math/rand"
	"time"

	"github.com/carlmjohnson/versioninfo"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
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
	var timeout int
	var concurrency int
	var printDiff bool
	var launch bool
	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.StringVar(&service, "s", "", "service name")
	flag.IntVar(&count, "n", 5, "count")
	flag.IntVar(&timeout, "t", 45, "timeout")
	flag.IntVar(&concurrency, "C", 1, "concurrency")
	flag.BoolVar(&printDiff, "printDiff", false, "print payload contents if reply is different than original")
	flag.BoolVar(&launch, "l", true, "Launch new client daemon if set to true, otherwise just connect to existing daemon.")
	version := flag.Bool("v", false, "Get version info.")
	flag.Parse()

	if *version {
		fmt.Printf("version is %s\n", versioninfo.Short())
		return
	}

	if service == "" {
		panic("must specify service name with -s")
	}

	cfg, err := config.LoadFile(configFile)
	if err != nil {
		panic(fmt.Errorf("failed to open config: %s", err))
	}

	if launch {
		d, err := client2.NewDaemon(cfg)
		if err != nil {
			panic(err)
		}
		err = d.Start()
		if err != nil {
			panic(err)
		}

		// XXX FIX ME
		time.Sleep(time.Second * 3)
	}

	thin := thin.NewThinClient(cfg)
	err = thin.Dial()
	if err != nil {
		panic(err)
	}

	doc := thin.PKIDocument()
	if doc == nil {
		panic("pki doc cannot be nil")
	}

	echoServices := common.FindServices(service, doc)
	if len(echoServices) == 0 {
		panic("wtf no echo services")
	}
	echoService := echoServices[mrand.Intn(len(echoServices))]

	sendPings(thin, echoService, count, concurrency, printDiff)

	err = thin.Close()
	if err != nil {
		panic(err)
	}
}
