package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/katzenpost/catshadow"
	catconfig "github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	"time"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/io/key"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

var (
	clientConfigFile = flag.String("f", "", "Path to the client config file.")
	stateFile        = flag.String("s", "catshadow_statefile", "The catshadow state file path.")

	catshadowClient *catshadow.Client
	catshadowCfg    *catconfig.Config

	minPasswordLen = 5 // XXX pick something reasonable

	lastMessages = make(map[string]*catshadow.Message)

	// theme
	th = func() *material.Theme {
		th := material.NewTheme(gofont.Collection())
		th.Bg = rgb(0x0)
		th.Fg = rgb(0xFFFFFFFF)
		th.ContrastBg = rgb(0x22222222)
		th.ContrastFg = rgb(0x33333333)
		return th
	}()

	status string
)

type App struct {
	w      *app.Window
	ops    *op.Ops
	client *catshadow.Client
	stack  pageStack
}

func newApp(w *app.Window) *App {
	a := &App{
		w:   w,
		ops: &op.Ops{},
	}
	return a
}

func (a *App) Layout(gtx layout.Context) {
	a.update(gtx)
	a.stack.Current().Layout(gtx)
}

func (a *App) update(gtx layout.Context) {
	page := a.stack.Current()
	if e := page.Event(gtx); e != nil {
		switch e := e.(type) {
		case BackEvent:
			a.stack.Pop()
		case signInStarted:
			a.stack.Clear(newConnectingPage(e.result))
			a.w.Invalidate()
		case connectError:
			a.stack.Clear(newSignInPage())
		case connectSuccess:
			a.stack.Clear(newHomePage())
		case AddContactClick:
			a.stack.Push(newAddContactPage())
		case AddContactComplete:
			a.stack.Pop()
		case ChooseContactClick:
			a.stack.Push(newConversationPage(e.nickname))
		case MessageSent:
		}
	}
}

func (a *App) run() error {
	var clientSink chan interface{}
	for {
		if a.client != nil {
			clientSink = a.client.EventSink
		}
		select {
		case e := <-clientSink:
			if err := a.handleCatshadowEvent(e); err != nil {
				return err
			}
		case e := <-a.w.Events():
			switch e := e.(type) {
			case key.Event:
				switch e.Name {
				case key.NameEscape:
					if a.stack.Len() > 1 {
						a.stack.Pop()
						a.w.Invalidate()
					}
				}
			case system.DestroyEvent:
				return e.Err
			case system.FrameEvent:
				gtx := layout.NewContext(a.ops, e)
				a.Layout(gtx)
				e.Frame(gtx.Ops)
			case system.StageEvent:
				fmt.Printf("StageEvent received with stage: %v", e.Stage)
				fmt.Printf("system.StageRunning: %v", system.StageRunning)
				if e.Stage >= system.StageRunning {
					if a.stack.Len() == 0 {
						a.stack.Push(newSignInPage())
					}
				}
			}
		}
	}
}

func main() {
	flag.Parse()

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

	fmt.Println("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	var err error
	// Load catshadow config file if specified or use baked-in defaults
	if len(*clientConfigFile) != 0 {
		catshadowCfg, err = catconfig.LoadFile(*clientConfigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *clientConfigFile, err)
			os.Exit(-1)
		}
	} else {
		// use the baked in configuration defaults if a configuration is not specified
		catshadowCfg, err = getDefaultConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config defaults: %v\n", err)
			os.Exit(-1)
		}
	}
	// Start graphical user interface.
	uiMain()
}

func uiMain() {
	go func() {
		w := app.NewWindow(
			app.Size(unit.Dp(400), unit.Dp(400)),
			app.Title("Catchat"),
		)
		if err := newApp(w).run(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
		}

		if catshadowClient != nil {
			catshadowClient.Shutdown()
			catshadowClient.Wait()
		}
		os.Exit(0)
	}()
	app.Main()
}

type (
	C = layout.Context
	D = layout.Dimensions
)

func getDefaultConfig() (*catconfig.Config, error) {
	cfgString := `
[UpstreamProxy]
  Type = "socks5"
  Network = "tcp"
  Address = "127.0.0.1:9050"

[Logging]
  Disable = false
  Level = "DEBUG"
  File = ""

[ClientLogging]
  Disable = false
  Level = "NOTICE"
  File = ""

[VotingAuthority]
[[VotingAuthority.Peers]]
  Addresses = ["n5axysudjvjjkpy4r7hur7qfgybfaiwrfz2mqwkvnyylqxinldtao2ad.onion:30000"]
  IdentityPublicKey = "EmUWxb6ocBBXhxlrAKgxVd/6tyIDVK/8pIY/nZrqSDQ="
  LinkPublicKey = "Mcfs706pyzBIvEj+k5t2L9t9x+LplOR4wz3RiVrgoVU="

[[VotingAuthority.Peers]]
  Addresses = ["mj5ouhyjvokgvbcp56lh56plxvzh4wcrq3fadpqf6ewdqmuy7pr3n6qd.onion:30000"]
  IdentityPublicKey = "vdOAeoRtWKFDw+W4k3sNN1EMT9ZsaHHmuCHOEKSg1aA="
  LinkPublicKey = "VNmU4g1hXBS7BQ1RJYMGNjNg4fIZbCimppeJ1XwrqX4="

[[VotingAuthority.Peers]]
  Addresses = ["pz6obnsyh7vmpmtmrsam443jh4gkei77q3y66ty3fd6h6wjdvcmu6pid.onion:30000"]
  IdentityPublicKey = "bFgvws69dJrc3ACKXN5aCJKLHjkN7D8DA2HDKkhSNIk="
  LinkPublicKey = "p1JekMh8uCPDsRSP5Uc59DJvEGMmA/B0mcMCXx1WEkk="

[Debug]
  CaseSensitiveUserIdentifiers = false
  PollingInterval = 500
  PreferedTransports = ["onion"]

[Panda]
  Receiver = "+panda"
  Provider = "provider1"
  BlobSize = 1000

[Reunion]
  Enable = false
`
	return catconfig.Load([]byte(cfgString))
}

func (a *App) handleCatshadowEvent(e interface{}) error {
	switch event := e.(type) {
	case *client.ConnectionStatusEvent:
		if event.IsConnected {
			// emit some notification event
		} else {
			// update connected state
		}
		if event.Err != nil {
			return event.Err
		}
	case *catshadow.KeyExchangeCompletedEvent:
		// emit some notification event
		//event.Nickname, event.Err
		if event.Err != nil {
			// add to notify queue?
		}
	case *catshadow.MessageSentEvent:
		msgs := catshadowClient.GetConversation(event.Nickname)
		if m, ok := msgs[event.MessageID]; ok {
			lastMessages[event.Nickname] = m // shouldn't this be updated earlier?
		}
	case *catshadow.MessageNotSentEvent:
		// message failed to send, notify
	case *catshadow.MessageDeliveredEvent:
		a.w.Invalidate()
		// the status will be updated next frame
	case *catshadow.MessageReceivedEvent:
		a.w.Invalidate()
		status = fmt.Sprintf("Message received from  %s", event.Nickname)
	}
	return nil
}
