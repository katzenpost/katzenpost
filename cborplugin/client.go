// client.go - client of cbor plugin system
// Copyright (C) 2021  David Stainton.
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

package cborplugin

import (
	"bufio"
	"io"
	"net"
	"os/exec"
	"syscall"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/worker"
)

type Client struct {
	worker.Worker

	logBackend *log.Backend
	log        *logging.Logger

	socketPath string
	cmd        *exec.Cmd
	conn       net.Conn

	endpoint   string
	capability string
	params     *Parameters

	readCh  chan Command
	writeCh chan Command

	commandBuilder CommandBuilder
}

// New creates a new plugin client instance which represents the single execution
// of the external plugin program.
func NewClient(logBackend *log.Backend, commandBuilder CommandBuilder, name, capability, endpoint string) *Client {
	return &Client{
		capability: capability,
		endpoint:   endpoint,
		logBackend: logBackend,
		log:        logBackend.GetLogger(name),
		readCh:     make(chan Command),
		writeCh:    make(chan Command),
	}
}

// Start execs the plugin and starts a worker thread to listen
// on the halt chan sends a TERM signal to the plugin if the shutdown
// even is dispatched.
func (c *Client) Start(command string, args []string) error {
	err := c.launch(command, args)
	if err != nil {
		return err
	}
	c.Go(c.reaper)
	c.Go(c.reader)
	c.Go(c.writer)
	return nil
}

func (c *Client) dialSocket(socketPath string) error {
	var err error
	c.conn, err = net.Dial("unix", socketPath)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) reaper() {
	<-c.HaltCh()
	c.cmd.Process.Signal(syscall.SIGTERM)
	err := c.cmd.Wait()
	if err != nil {
		c.log.Errorf("CBOR plugin worker, command exec error: %s\n", err)
	}
}

func (c *Client) logPluginStderr(stderr io.ReadCloser) {
	logWriter := c.logBackend.GetLogWriter(c.cmd.Path, "DEBUG")
	_, err := io.Copy(logWriter, stderr)
	if err != nil {
		c.log.Errorf("Failed to proxy cborplugin stderr to DEBUG log: %s", err)
	}
	c.Halt()
}

func (c *Client) launch(command string, args []string) error {
	// exec plugin
	c.cmd = exec.Command(command, args...)
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		c.log.Debugf("pipe failure: %s", err)
		return err
	}
	stderr, err := c.cmd.StderrPipe()
	if err != nil {
		c.log.Debugf("pipe failure: %s", err)
		return err
	}
	err = c.cmd.Start()
	if err != nil {
		c.log.Debugf("failed to exec: %s", err)
		return err
	}

	// proxy stderr to our debug log
	c.Go(func() {
		c.logPluginStderr(stderr)
	})

	// read and decode plugin stdout
	stdoutScanner := bufio.NewScanner(stdout)
	stdoutScanner.Scan()
	c.socketPath = stdoutScanner.Text()
	c.log.Debugf("plugin socket path:'%s'\n", c.socketPath)
	c.dialSocket(c.socketPath)

	c.log.Debug("finished launching plugin.")
	return nil
}

func (c *Client) readCommand() (Command, error) {
	cmd := c.commandBuilder.Build()
	err := readCommand(c.conn, cmd)
	if err != nil {
		return nil, err
	}

	return cmd, nil
}

func (c *Client) writeCommand(cmd Command) error {
	return writeCommand(c.conn, cmd)
}

func (c *Client) reader() {
	for {
		cmd, err := c.readCommand()
		if err != nil {
			panic(err) // XXX
		}
		select {
		case <-c.HaltCh():
			return
		case c.readCh <- cmd:
		}
	}

}

func (c *Client) writer() {
	for {
		select {
		case <-c.HaltCh():
			return
		case cmd := <-c.writeCh:
			err := c.writeCommand(cmd)
			if err != nil {
				panic(err) // XXX
			}
		}
	}
}

// Capability are used in Mix Descriptor publication to give
// service clients more information about the service.
func (c *Client) Capability() string {
	return c.capability
}
