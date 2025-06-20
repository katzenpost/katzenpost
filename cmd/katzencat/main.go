package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/stream"
	"io"
	"os"
	"os/signal"
	"sync"
	"time"
)

const (
	keySize           = 32
	progressChunkSize = 4096 // 4kb
)

var cConf = flag.String("cfg", "client.toml", "config file")

func getSession() (*client.Session, error) {
	cfg, err := config.LoadFile(*cConf)
	if err != nil {
		return nil, err
	}
	cfg.Logging.File = "/dev/null" // noisy garbage
	cc, err := client.New(cfg)
	if err != nil {
		return nil, err
	}
	for {
		session, err := cc.NewTOFUSession(context.Background())
		switch err {
		case nil:
		case pki.ErrNoDocument:
			_, _, till := epochtime.Now()
			<-time.After(till)
			continue
		default:
			return nil, err
		}
		session.WaitForDocument(context.Background())
		return session, nil
	}
}

func main() {
	secret := flag.String("s", "", "Secret given by initiator, or empty if initiating")
	flag.Parse()

	s, err := getSession()
	if err != nil {
		panic(err)
	}

	var st *stream.Stream
	if *secret == "" {
		st, _ = stream.NewDuplex(s)
		*secret = st.RemoteAddr().String()
		fmt.Fprintln(os.Stderr, "KatzenCat secret:", *secret)
	} else {
		st, err = stream.DialDuplex(s, "", *secret)
		if err != nil {
			panic(err)
		}
	}

	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(st, os.Stdin)
		st.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(os.Stdout, st)
		st.Close()
	}()
	// catch ctrl-C and kill stream
	intc := make(chan os.Signal, 1)
	haltchan := make(chan bool, 0)
	signal.Notify(intc, os.Interrupt)
	go func() {
		for _ = range intc {
			fmt.Fprintln(os.Stderr, "ctrl-c caught")
			st.Close()
			close(haltchan)
			break
		}
	}()

	wg.Wait()
	st.Close()
	fmt.Fprintln(os.Stderr, "halting gracefully")
	// it seems that messages may get lost in the send queue if exit happens immediately after Close()
	select {
	case <-time.After(5 * time.Second):
	case <-haltchan:
	}
	s.Shutdown()
}
