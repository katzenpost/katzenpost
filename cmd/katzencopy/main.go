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

func validateArgs(secret, inFile, outFile string) {
	if secret == "" && inFile == "" {
		fmt.Println("Must specify input file")
		os.Exit(-1)
	}
	if secret != "" && outFile == "" {
		fmt.Println("Must specify output file")
		os.Exit(-1)
	}
}

func sendLengthPrefix(st *stream.Stream, length uint64) {
	lengthprefix := make([]byte, 8)
	binary.BigEndian.PutUint64(lengthprefix, length)
	for {
		_, err := st.Write(lengthprefix)
		if err == nil {
			break
		}
	}
}

func sendFile(st *stream.Stream, filename string) error {
	fi, err := os.Stat(filename)
	if err != nil {
		return err
	}

	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	sendLengthPrefix(st, uint64(fi.Size()))

	total := int64(0)
	for total < fi.Size() {
		limited := io.LimitReader(f, progressChunkSize)
		n, err := io.Copy(st, limited)
		total += n
		if err == io.EOF {
			return fmt.Errorf("unexpected EOF of limitReader")
		}
		fmt.Fprintf(os.Stderr, "\rWrite(%d/%d)", total, fi.Size())
	}
	return nil
}

func waitForAcknowledgment(st *stream.Stream) {
	fmt.Fprintln(os.Stderr, "\nTransfer completed, waiting for peer to close stream")
	for {
		_, err := io.ReadAll(st)
		if err == nil || err == io.EOF {
			break
		}
	}
	fmt.Fprintln(os.Stderr, "\nTransfer acknowledged, shutting down")
}

func readLengthPrefix(st *stream.Stream) (uint64, error) {
	lengthprefix := make([]byte, 8)
	n := 0
	for n < 8 {
		bytesRead, err := st.Read(lengthprefix[n:])
		n += bytesRead
		if err != nil {
			continue
		}
	}
	return binary.BigEndian.Uint64(lengthprefix), nil
}

func receiveFile(st *stream.Stream, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	payloadlen, err := readLengthPrefix(st)
	if err != nil {
		return err
	}

	total := uint64(0)
	for total < payloadlen {
		limitsize := int64(progressChunkSize)
		if total+progressChunkSize > payloadlen {
			limitsize = int64(payloadlen - total)
		}

		limited := io.LimitReader(st, limitsize)
		nn, err := io.Copy(f, limited)
		total += uint64(nn)

		if err == os.ErrDeadlineExceeded {
			continue
		}
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "\rRead(%d/%d)", total, payloadlen)
	}

	fmt.Fprintln(os.Stderr, "\nTransfer completed, closing stream")
	return nil
}

func runAsInitiator(s *client.Session, inFile string) error {
	st := stream.NewStream(s)
	secret := st.RemoteAddr().String()
	fmt.Println("KatzenCat secret:", secret)

	if err := sendFile(st, inFile); err != nil {
		return err
	}

	waitForAcknowledgment(st)
	st.Close()
	return nil
}

func runAsReceiver(s *client.Session, secret, outFile string) error {
	st, err := stream.DialDuplex(s, "", secret)
	if err != nil {
		return err
	}
	defer st.Close()

	return receiveFile(st, outFile)
}

func main() {
	secret := flag.String("s", "", "Secret given by initiator, or empty if initiating")
	flag.Parse()

	validateArgs(*secret, *inFile, *outFile)

	s, err := getSession()
	if err != nil {
		panic(err)
	}
	defer func() {
		// it seems that messages may get lost in the send queue if exit happens immediately after Close()
		<-time.After(10 * time.Second)
		s.Shutdown()
		s.Wait()
	}()

	isInitiator := *secret == ""
	if isInitiator {
		err = runAsInitiator(s, *inFile)
	} else {
		err = runAsReceiver(s, *secret, *outFile)
	}

	if err != nil {
		panic(err)
	}
}
