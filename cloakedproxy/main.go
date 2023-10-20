package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"gioui.org/app"
	_ "gioui.org/app/permission/foreground"
	_ "gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/worker"
	kclient "github.com/katzenpost/katzenpost/katzensocks/client"
	"image/color"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

const (
	initialPKIConsensusTimeout = 120 * time.Second
)

var (
	// application command line falgs
	clientConfigFile = flag.String("cfg", "", "Path to the client config file.")
	socksPort        = flag.Int("socks_port", 4242, "SOCKS5 TCP listening port")

	// socks port selector
	portSelect = &PortSelect{Editor: &widget.Editor{SingleLine: true, Submit: true, Filter: "0123456789"}}
	debug      = flag.Int("d", 0, "Port for net/http/pprof listener")

	// wallet state
	wallet = &Wallet{Balance: 0}

	// application theme
	th = func() *material.Theme {
		th := material.NewTheme()
		// XXX: for some reason I get no fonts when building/running in podman alpine without the next line
		th.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(gofont.Regular()))
		th.Bg = rgb(0x55555555)
		th.Fg = rgb(0x00FF0000)
		th.ContrastBg = rgb(0x22222222)
		th.ContrastFg = rgb(0x77777777)
		return th
	}()

	// proxy connected toggle:
	connected widget.Bool

	//go:embed default_config_without_tor.toml
	cfgWithoutTor []byte
	//go:embed default_config_with_tor.toml
	cfgWithTor []byte
)

type (
	C = layout.Context
	D = layout.Dimensions
)

func argb(c uint32) color.NRGBA {
	return color.NRGBA{A: uint8(c >> 24), R: uint8(c >> 16), G: uint8(c >> 8), B: uint8(c)}
}

func rgb(c uint32) color.NRGBA {
	return argb((0xff << 24) | c)
}

type Wallet struct {
	Balance int
}

func (w *Wallet) Layout(gtx C) D {
	return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Start}.Layout(gtx,
			layout.Rigid(material.H6(th, "Balance").Layout),
			layout.Rigid(material.H6(th, fmt.Sprintf("%d", w.Balance)).Layout),
		)
	})
}

// widget to select socks proxy port
type PortSelect struct {
	Editor *widget.Editor
}

// Layout renders the port selector widget
func (p *PortSelect) Layout(gtx C) D {
	return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Start}.Layout(gtx,
			layout.Rigid(material.H6(th, "SOCKS5 Port").Layout),
			layout.Rigid(material.Editor(th, p.Editor, "port").Layout),
		)
	})
}

// Update processes the Editor events and validates the input
func (p *PortSelect) Update() {
	for _, e := range p.Editor.Events() {
		switch e.(type) {
		case widget.SubmitEvent:
			ap := "127.0.0.1:" + p.Editor.Text()
			addr, err := netip.ParseAddrPort(ap)
			if err != nil {
				log.Print(err)
			} else {
				port := int(addr.Port())
				if port >= 1024 {
					*socksPort = port
				} else {
					log.Printf("port %d too low (<1024)", port)
				}
			}
			p.Editor.SetText(fmt.Sprintf("%d", *socksPort))
		}
	}
}

type App struct {
	endBg func()
	sync.Mutex
	worker.Worker
	w   *app.Window
	c   *client.Client
	ops *op.Ops

	connect     *widget.Clickable
	connectOnce *sync.Once
	clicked     chan struct{}
}

func (a *App) run() error {

	for {
		select {
		case e := <-a.w.Events():
			if err := a.handleGioEvents(e); err != nil {
				return err
			}
		case <-time.After(1 * time.Minute):
			// redraw the screen to update the message timestamps once per minute
			a.w.Invalidate()
		}
	}
}

func (a *App) handleGioEvents(e interface{}) error {
	switch e := e.(type) {
	case system.DestroyEvent:
		return errors.New("system.DestroyEvent receieved")
	case system.FrameEvent:
		gtx := layout.NewContext(a.ops, e)
		a.Update()
		a.Layout(gtx)
		e.Frame(gtx.Ops)
	case system.StageEvent:
		a.Lock()
		if e.Stage == system.StagePaused {
			a.endBg, _ = app.Start("Is running in the background", "")
		} else {
			if a.endBg != nil {
				a.endBg()
				a.endBg = nil
			}
		}
		a.Unlock()
	}
	return nil
}

// Update reads events from the app elements
func (a *App) Update() {
	portSelect.Update()
	a.updateConnectedSwitch()
}

func (a *App) updateConnectedSwitch() {
	a.Lock()
	defer a.Unlock()
	if connected.Changed() {
		go a.doConnectClick()
	}
}

// This is the main app layout
func (a *App) Layout(gtx layout.Context) {
	// display connected status
	// display disconnect/connect button
	layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceAround, Alignment: layout.Baseline}.Layout(gtx,
		// wallet balance
		layout.Rigid(wallet.Layout),
		// Proxy Port Selector
		layout.Rigid(portSelect.Layout),
		// layout the exit node selection
		//layout.Rigid(exitSelect.Layout),
		layout.Rigid(material.Switch(th, &connected, "").Layout),
	)
}

func (a *App) doConnectClick() {
	a.clicked <- struct{}{}
	a.connectOnce.Do(func() {
		<-a.clicked
		ctx, cancel := context.WithTimeout(context.Background(), initialPKIConsensusTimeout)
		s, err := a.c.NewTOFUSession(ctx)
		if err != nil {
			// raise error to application notification
			cancel()
			a.Lock()
			a.connectOnce = new(sync.Once)
			connected.Value = false
			a.Unlock()
			return
		}

		// create a katzensocks client
		kc, err := kclient.NewClient(s)
		if err != nil {
			log.Fatal(err)
		}

		// add SOCKS5 listener
		a.Go(func() {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *socksPort))
			if err != nil {
				log.Fatal(err)
			}
			// Close connection when katzensocks client is halted
			a.Go(func() {
				<-kc.HaltCh()
				ln.Close()
			})
			for {
				conn, err := ln.Accept()
				if err != nil {
					if e, ok := err.(net.Error); ok && !e.Temporary() {
						return
					}
					continue
				}
				a.Go(func() {
					kc.SocksHandler(conn)
				})
			}
		})

		// cleanup at session exit
		a.Go(func() {
			select {
			case <-s.HaltCh():
			case <-a.clicked:
				kc.Halt()
				kc.Wait()
				s.Shutdown()
			}
			a.Lock()
			a.connectOnce = new(sync.Once)
			connected.Value = false
			a.Unlock()
		})
	})
}

func main() {

	flag.Parse()
	portSelect.Editor.SetText(fmt.Sprintf("%d", *socksPort))
	go func() {
		w := app.NewWindow(
			//app.Size(unit.Dp(400), unit.Dp(400)),
			app.Title("CloakedProxy"),
			app.NavigationColor(rgb(0x0)),
			app.StatusColor(rgb(0x0)),
		)
		c, err := setupClient()
		if err != nil {
			log.Fatal(err)
		}
		a := &App{
			c:           c,
			w:           w,
			clicked:     make(chan struct{}, 2),
			connect:     &widget.Clickable{},
			ops:         &op.Ops{},
			connectOnce: new(sync.Once),
		}
		if err := a.run(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
		}
		os.Exit(0)
	}()
	app.Main()
}

func setupClient() (*client.Client, error) {
	var cfg *config.Config
	var err error
	if len(*clientConfigFile) != 0 {
		cfg, err = config.LoadFile(*clientConfigFile)
		if err != nil {
			return nil, err
		}
	} else {
		// detect running Tor and use configuration
		var useTor = false
		if hasDefaultTor() {
			useTor = true
		}
		if useTor {
			cfg, err = config.Load(cfgWithTor)
			if err != nil {
				return nil, err
			}
		} else {
			cfg, err = config.Load(cfgWithoutTor)
			if err != nil {
				return nil, err
			}
		}
	}

	// create a client
	return client.New(cfg)
}

// checks to see if the local system has a listener on port 9050
func hasDefaultTor() bool {
	c, err := net.Dial("tcp", "127.0.0.1:9050")
	if err != nil {
		return false
	}
	c.Close()
	return true
}
