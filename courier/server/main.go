// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/courier/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type Courier struct {
	write func(cborplugin.Command)
}

func (e *Courier) OnCommand(cmd cborplugin.Command) error {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		courierMessage, err := common.CourierMessageFromBytes(r.Payload)
		if err != nil {
			return err
		}

		for _, replicaID := range courierMessage.Replicas {

		}

		replyPayload := []byte{} // XXX FIX ME
		go func() {
			// send reply
			e.write(&cborplugin.Response{ID: r.ID, SURB: r.SURB, Payload: replyPayload})
		}()
		return nil
	default:
		return errors.New("courier-plugin: Invalid Command type")
	}
}

func (e *Courier) RegisterConsumer(s *cborplugin.Server) {
	e.write = s.Write
}

func main() {
	var logLevel string
	var logDir string
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

	// Ensure that the log directory exists.
	s, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		fmt.Printf("Log directory '%s' doesn't exist.", logDir)
		os.Exit(1)
	}
	if !s.IsDir() {
		fmt.Println("Log directory must actually be a directory.")
		os.Exit(1)
	}

	// Log to a file.
	logFile := path.Join(logDir, fmt.Sprintf("courier.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("courier_server")

	// start service
	tmpDir, err := os.MkdirTemp("", "courier_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.courier.socket", os.Getpid()))
	courier := new(Courier)

	var server *cborplugin.Server
	server = cborplugin.NewServer(serverLog, socketFile, new(cborplugin.RequestFactory), courier)
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	err = os.Remove(socketFile)
	if err != nil {
		panic(err)
	}
}
