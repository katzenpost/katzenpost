package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/stream"
)

const (
	keySize           = 32
	progressChunkSize = 4096 // 4kb
)

var cConf = flag.String("cfg", "client.toml", "config file")
var outFile = flag.String("o", "", "file to write to")
var inFile = flag.String("i", "", "file to write to")

func getSession() (*client.Session, error) {
	cfg, err := config.LoadFile(*cConf)
	cfg.Logging.Level = "NOTICE"
	if err != nil {
		return nil, err
	}
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

	if *secret == "" && *inFile == "" {
		fmt.Println("Must specify input file")
		os.Exit(-1)
	}
	if *secret != "" && *outFile == "" {
		fmt.Println("Must specify output file")
		os.Exit(-1)
	}

	s, err := getSession()
	if err != nil {
		panic(err)
	}

	var st *stream.Stream
	isinitiator := *secret == ""
	if *secret == "" {
		st = stream.NewStream(s)
		*secret = st.RemoteAddr().String()
		fmt.Println("KatzenCat secret:", *secret)
	}
	if isinitiator {
		fi, err := os.Stat(*inFile)
		if err != nil {
			panic(err)
		}
		f, err := os.Open(*inFile)
		if err != nil {
			panic(err)
		}
		lengthprefix := make([]byte, 8)
		binary.BigEndian.PutUint64(lengthprefix, uint64(fi.Size()))
		for {
			_, err := st.Write(lengthprefix)
			if err == nil {
				break
			}
		}
		total := int64(0)
		for total < fi.Size() {
			limited := io.LimitReader(f, progressChunkSize)
			n, err := io.Copy(st, limited)
			total += n
			if err == io.EOF {
				panic("wtf, EOF of limitReader")
			} else {
				fmt.Fprintf(os.Stderr, "\rWrite(%d/%d)", total, fi.Size())
				continue
			}
		}
		fmt.Fprintln(os.Stderr, "\nTransfer completed, waiting for peer to close stream")
		// try to read a response from the client until defaultTimeout, and log status
		for {
			_, err := io.ReadAll(st)
			if err == nil || err == io.EOF {
				break
			}
		}
		// Teardown the sender side stream
		fmt.Fprintln(os.Stderr, "\nTransfer acknowledged, shutting down")
		st.Close()
	} else {
		st, err := stream.DialDuplex(s, "", *secret)
		if err != nil {
			panic(err)
		}
		f, err := os.Create(*outFile)
		if err != nil {
			panic(err)
		}
		n := 0
		lengthprefix := make([]byte, 8)
		for n < 8 {
			n, err = st.Read(lengthprefix[n:])
			if err != nil {
				continue
			}
		}
		payloadlen := binary.BigEndian.Uint64(lengthprefix)
		total := uint64(0)
		for total < payloadlen {
			limitsize := int64(progressChunkSize)
			if total+progressChunkSize > payloadlen {
				limitsize = int64(payloadlen - total)
			}
			limited := io.LimitReader(st, int64(limitsize))
			nn, err := io.Copy(f, limited)
			total += uint64(nn)
			if err == os.ErrDeadlineExceeded {
				continue
			}
			if err != nil {
				panic(err)
			}

			fmt.Fprintf(os.Stderr, "\rRead(%d/%d)", total, payloadlen)
		}
		fmt.Fprintln(os.Stderr, "\nTransfer completed, closing stream")
		st.Close()
		f.Close()
	}
	// it seems that messages may get lost in the send queue if exit happens immediately after Close()
	<-time.After(10 * time.Second)
	s.Shutdown()
	s.Wait()
}
