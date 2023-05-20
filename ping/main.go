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
	"os"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/katzenpost/katzenpost/client/config"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

type errMsg error

type model struct {
	state    string
	pingFSM  *PingFSM
	spinner  spinner.Model
	quitting bool
	err      error
}

func initialModel(fsm *PingFSM) model {
	s := spinner.New()
	s.Spinner = spinner.Line
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	return model{
		spinner: s,
		state:   "init",
		pingFSM: fsm,
	}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			m.pingFSM.Stop()
			return m, tea.Quit
		default:
			return m, nil
		}
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case errMsg:
		m.err = msg
		return m, nil
	default:
		switch m.state {
		case "init":
			m.state = "connecting"
			m.pingFSM.Connect()
		case "connecting":
			m.state = "connected"
			m.pingFSM.WaitForDocument()
		case "connected":
			m.pingFSM.Ping()
		}
		return m, nil
	}
}

func (m model) View() string {
	if m.err != nil {
		return m.err.Error()
	}
	if m.quitting {
		return "aborting...\n\n\n"
	}

	status := ""
	switch m.state {
	case "init":
		status = "Connecting to mixnet"
	case "connecting":
		status = "Waiting for PKI doc"
	case "connected":
		status = "Sending pings"
	}
	return fmt.Sprintf("\n\n %s %s...\n\n", m.spinner.View(), status)
}

func main() {
	var configFile string
	var service string
	var count int
	var timeout int
	var concurrency int
	var printDiff bool
	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.StringVar(&service, "s", "echo", "service name")
	flag.IntVar(&count, "n", 5, "count")
	flag.IntVar(&timeout, "t", 45, "timeout")
	flag.IntVar(&concurrency, "C", 1, "concurrency")
	flag.BoolVar(&printDiff, "printDiff", false, "print payload contents if reply is different than original")
	flag.Parse()

	if service == "" {
		panic("must specify service name with -s")
	}

	fmt.Printf("%s\n", startupBanner)

	cfg, err := config.LoadFile(configFile)
	if err != nil {
		panic(fmt.Errorf("failed to open config: %s", err))
	}

	if cfg.Logging.File == "" {
		cfg.Logging.File = "/tmp/ping_output.log"
		fmt.Printf("Logging was set to STDOUT but instead logging to %s\n", cfg.Logging.File)
	}

	desc := &PingDescriptor{
		Timeout:     time.Duration(timeout) * time.Second,
		ServiceName: service,
		Concurrency: concurrency,
		PrintDiff:   printDiff,
		Count:       count,
	}

	m := initialModel(FromConfig(cfg, desc))

	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("could not run program:", err)
		os.Exit(1)
	}
}
