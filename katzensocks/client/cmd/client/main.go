package main

import (
	"github.com/katzenpost/katzenpost/katzensocks/client"
	"github.com/katzenpost/katzenpost/client/utils"

	"flag"
	"fmt"
	"context"
	"net"
	"sync"
	"time"
)

var (
	cfgFile = flag.String("cfg", "katzensocks.toml", "config file")
	gateway = flag.String("gw", "", "gateway provider name, default uses random gateway for each connection")
	pkiOnly = flag.Bool("list", false, "fetch and display pki and gateways, does not connect")
	port    = flag.Int("port", 4242, "listener address")
	retry   = flag.Int("retry", -1, "limit number of reconnection attempts")
	delay   = flag.Int("delay", 30, "time to wait between connection attempts (seconds)>")
)

func showPKI() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*delay) * time.Second)
	defer cancel()

	_, doc, err := client.GetPKI(ctx, *cfgFile)
	if err != nil {
		panic(err)
	}
	// display the pki.Document
	fmt.Println(doc.String())

	// display the gateway services
	descs := utils.FindServices("katzensocks", doc)
	for _, desc := range descs {
		fmt.Println(desc)
	}
}

func main() {
	flag.Parse()
	if *pkiOnly {
		showPKI()
		return
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		panic(err)
	}

	s, err := client.GetSession(*cfgFile, *delay, *retry)
	if err != nil {
		panic(err)
	}

	c, err := client.NewClient(s)
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		_ = socksAcceptLoop(c, ln)
		wg.Done()
	}()
	/*
		TODO: Add a HTTP3 CONNECT proxy listener that uses QUIC Datagram to proxy QUIC UDP connections
		wg.Add(1)
		go func() {
			_ = httpAcceptLoop(s, ..
	*/
	// wait until loop has exited
	wg.Wait()
}

func socksAcceptLoop(c *client.Client, ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go c.SocksHandler(conn)
	}
}
