package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"syscall"

	"github.com/katzenpost/catshadow"
	catconfig "github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	clientConfig "github.com/katzenpost/client/config"
	"time"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/io/key"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

var (
	config Config

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

	status    string

	// persistent views (maintain state between frames)
	contactList  = &layout.List{Axis: layout.Vertical, ScrollToEnd: false}
	messageList  = &layout.List{Axis: layout.Vertical, ScrollToEnd: true}
	messageField = &widget.Editor{SingleLine: true}
)

func setupCatShadow(catshadowCfg *catconfig.Config, passphrase []byte, result chan interface{}) {
	// XXX: if the catshadowClient already exists, shut it down
	// FIXME: figure out a better way to toggle connected/disconnected
	// states and allow to retry attempts on a timeout or other failure.
	if catshadowClient != nil {
		catshadowClient.Shutdown()
	}
	var stateWorker *catshadow.StateWriter
	var state *catshadow.State
	cfg, err := catshadowCfg.ClientConfig()
	if err != nil {
		result <- err
		return
	}

	// automatically create a statefile if one does not already exist
	// TODO: pick a sensible location for a default statefile other than cwd
	if _, err := os.Stat(*stateFile); os.IsNotExist(err) {
		cfg, linkKey := client.AutoRegisterRandomClient(cfg)
		c, err := client.New(cfg)
		if err != nil {
			result <- err
			return
		}

		// Create statefile.
		stateWorker, err = catshadow.NewStateWriter(c.GetLogger("catshadow_state"), *stateFile, passphrase)
		if err != nil {
			result <- err
			c.Shutdown()
			return
		}
		// Start the stateworker
		stateWorker.Start()
		fmt.Println("creating remote message receiver spool")
		backendLog, err := catshadowCfg.InitLogBackend()
		if err != nil {
			result <- err
			stateWorker.Halt()
			c.Shutdown()
			return
		}

		user := fmt.Sprintf("%x", linkKey.PublicKey().Bytes())
		catshadowClient, err = catshadow.NewClientAndRemoteSpool(backendLog, c, stateWorker, user, linkKey)
		if err != nil {
			result <- err
			stateWorker.Halt()
			c.Shutdown()
			return
		}
		fmt.Println("catshadow client successfully created")
	} else {
		cfg, _ := client.AutoRegisterRandomClient(cfg)

		// Load previous state to setup our current client state.
		backendLog, err := catshadowCfg.InitLogBackend()
		if err != nil {
			result <- err
			return
		}
		stateWorker, state, err = catshadow.LoadStateWriter(backendLog.GetLogger("state_worker"), *stateFile, passphrase)
		if err != nil {
			result <- err
			return
		}
		// Start the stateworker
		stateWorker.Start()
		cfg.Account = &clientConfig.Account{
			User:     state.User,
			Provider: state.Provider,
		}

		// Run a Client.
		c, err := client.New(cfg)
		if err != nil {
			stateWorker.Halt()
			result <- err
			return
		}

		// Make a catshadow Client.
		catshadowClient, err = catshadow.New(backendLog, c, stateWorker, state)
		if err != nil {
			c.Shutdown()
			stateWorker.Halt()
			result <- err
			return
		}
	}

	// Start catshadow client.
	catshadowClient.Start()
	result <- nil
}

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
			a.w.Invalidate()
		case AddContactClick:
			a.stack.Push(newAddContactPage())
			a.w.Invalidate()
		case AddContactComplete:
			a.stack.Pop()
			a.w.Invalidate()
		case ChooseContactClick:
			a.stack.Push(newConversationPage(e.nickname))
			a.w.Invalidate()
		case MessageSent:
			a.w.Invalidate()
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
			switch event := e.(type) {
			case *client.ConnectionStatusEvent:
				if event.IsConnected {
					status = "Connected"
					// emit some notification event
				} else {
					status = "Disconnected"
				}
				if event.Err != nil {
					// emit some error efvent
				}
			case *catshadow.KeyExchangeCompletedEvent:

				// emit some notification event
				//event.Nickname, event.Err
				if event.Err != nil {
					// add to notify queue?
				}
				status = fmt.Sprintf("Key Exchanged with %s", event.Nickname)
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

type sortedContacts []string

func (s sortedContacts) Less(i, j int) bool {
	return s[i] < s[j]
}
func (s sortedContacts) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s sortedContacts) Len() int {
	return len(s)
}

func getSortedContacts() (contacts sortedContacts) {
	if catshadowClient == nil {
		return
	}

	// returns map[string]*Contact
	for nick, _ := range catshadowClient.GetContacts() {
		contacts = append(contacts, nick)
	}
	sort.Sort(contacts)
	return
}

type conversationPage struct {
	nickname string
	compose  *widget.Editor
	send     *widget.Clickable
}

func (c *conversationPage) Start(stop <-chan struct{}) {
}

type MessageSent struct {
	nickname string
	msgId    catshadow.MessageID
}

func (c *conversationPage) Event(gtx layout.Context) interface{} {
	// receive keystroke to editor panel
	for _, ev := range c.compose.Events() {
		switch ev.(type) {
		case widget.SubmitEvent:
			c.send.Click()
		}
	}
	if c.send.Clicked() {
		msg := c.compose.Text()
		c.compose.SetText("")
		msgId := catshadowClient.SendMessage(c.nickname, []byte(msg))
		return MessageSent{nickname: c.nickname, msgId: msgId}
	}

	return nil
}

func layoutMessage(gtx C, msg *catshadow.Message) D {
	ts := msg.Timestamp.Round(1 * time.Minute).Format(time.RFC822)

	status := ""
	if msg.Outbound == true {
		status = "queued"
		if msg.Sent {
			status = "sent"
		}
		if msg.Delivered {
			status = "delivered"
		}
	}

	return layout.Flex{Axis: layout.Vertical, Alignment: layout.End, Spacing: layout.SpaceBetween}.Layout(gtx,
		layout.Rigid(material.Body1(th, string(msg.Plaintext)).Layout),
		layout.Rigid(func(gtx C) D {
			in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
			return in.Layout(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.End, Spacing: layout.SpaceBetween}.Layout(gtx,
					layout.Rigid(material.Body2(th, ts).Layout),
					layout.Rigid(material.Body2(th, status).Layout),
				)
			})
		}),
	)
}

func (c *conversationPage) Layout(gtx layout.Context) layout.Dimensions {
	contact := catshadowClient.GetContacts()[c.nickname]
	messages := catshadowClient.GetSortedConversation(c.nickname)
	c.compose.Focus()
	bgl := Background{
		Color: th.Bg,
		Inset: layout.Inset{Top: unit.Dp(0), Bottom: unit.Dp(0), Left: unit.Dp(0), Right: unit.Dp(0)},
	}

	return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceBetween, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return bgl.Layout(gtx, func(gtx C) D { return layout.Center.Layout(gtx, material.Caption(th, c.nickname).Layout) })
		}),
		layout.Flexed(2, func(gtx C) D {
			return bgl.Layout(gtx, func(ctx C) D {
				if len(messages) == 0 {
					return fill{th.Bg}.Layout(ctx)
				}
				return messageList.Layout(gtx, len(messages), func(gtx C, i int) layout.Dimensions {
					bgSender := Background{
						Color:  th.ContrastBg,
						Inset:  layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(8), Right: unit.Dp(12)},
						Radius: unit.Dp(10),
					}
					bgReceiver := Background{
						Color:  th.ContrastFg,
						Inset:  layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(8)},
						Radius: unit.Dp(10),
					}
					if messages[i].Outbound {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline, Spacing: layout.SpaceAround}.Layout(gtx,
							layout.Flexed(1, fill{th.Bg}.Layout),
							layout.Flexed(5, func(gtx C) D {
								return bgSender.Layout(gtx, func(gtx C) D {
									return layoutMessage(gtx, messages[i])
								})
							}),
						)
					} else {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline, Spacing: layout.SpaceAround}.Layout(gtx,
							layout.Flexed(5, func(gtx C) D {
								return bgReceiver.Layout(gtx, func(gtx C) D {
									return layoutMessage(gtx, messages[i])
								})
							}),
							layout.Flexed(1, fill{th.Bg}.Layout),
						)
					}
				})
			})
		}),
		layout.Rigid(func(gtx C) D {
			bg := Background{
				Color: th.ContrastBg,
				Inset: layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(0), Left: unit.Dp(12), Right: unit.Dp(12)},
			}
			if contact.IsPending {
				return bg.Layout(gtx, material.Caption(th, "Contact pending key exchange").Layout)
			}
			return bg.Layout(gtx, material.Editor(th, c.compose, ">").Layout)
		}),
	)
}

func newConversationPage(nickname string) *conversationPage {
	return &conversationPage{nickname: nickname,
		compose: &widget.Editor{SingleLine: true, Submit: true},
		send:    &widget.Clickable{}}
}

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
