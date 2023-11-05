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
	"gioui.org/gesture"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/katzensocks/cashu"
	kclient "github.com/katzenpost/katzenpost/katzensocks/client"
	qrcode "github.com/skip2/go-qrcode"
	"image"
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
	cashuAPI         = flag.String("cashu_api", "http://127.0.0.1:4448", "Cashu wallet API endpoint")
	cli              = flag.Bool("cli", false, "cli mode")

	// socks port selector
	portSelect    = &PortSelect{Editor: &widget.Editor{SingleLine: true, Submit: true, Filter: "0123456789"}}
	debug         = flag.Int("d", 0, "Port for net/http/pprof listener")
	invoiceAmount = 42

	// wallet state
	wallet = &Wallet{balance: 0}

	// invoice display
	invoice = &Invoice{amount: int64(invoiceAmount), amountEd: &widget.Editor{SingleLine: true, Submit: true, Filter: "0123456789"}, clicked: new(gesture.Click)}

	// cashu wallet api client
	cwallet = cashu.NewCashuApiClient(nil, *cashuAPI)

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
	connectSwitch =  ConnectSwitch{connected: new(widget.Bool)}

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

// ConnectSwitch is a widget to display the on/off switch
type ConnectSwitch struct {
	sync.Mutex
	connected *widget.Bool
}

func (c *ConnectSwitch) Off() {
	c.Lock()
	c.connected.Value = false
	defer c.Unlock()
}

func (c *ConnectSwitch) On() {
	c.Lock()
	c.connected.Value = true
	defer c.Unlock()
}

func (c *ConnectSwitch) Layout(gtx C) D {
	return material.Switch(th, c.connected, "Connect").Layout(gtx)
}

// Invoice is a widget to display a lightning invoice to buy nuts
type Invoice struct {
	// TODO: obtain data from these cashu api objects
	// casu.InvoiceRequest
	// casu.Invoice Response
	// casu.Payment Status
	sync.Mutex
	paymentRequest string
	amount   int64
	amountEd *widget.Editor

	clicked *gesture.Click
}

func (i *Invoice) QR() (*qrcode.QRCode, error) {
	i.Lock()
	defer i.Unlock()
	return qrcode.New(i.paymentRequest, qrcode.High)
}

func (i *Invoice) layoutQr(gtx C) D {
	in := layout.Inset{}
	dims := in.Layout(gtx, func(gtx C) D {
		x := gtx.Constraints.Max.X
		y := gtx.Constraints.Max.Y
		if x > y {
			x = y
		}

		sz := image.Point{X: x, Y: x}
		gtx.Constraints = layout.Exact(gtx.Constraints.Constrain(sz))
		qr, err := i.QR()
		if err != nil {
			return layout.Center.Layout(gtx, material.Caption(th, "Get Invoice").Layout)
		}
		qr.BackgroundColor = th.Bg
		qr.ForegroundColor = th.Fg

		i := qr.Image(x)
		return widget.Image{Fit: widget.ScaleDown, Src: paint.NewImageOp(i)}.Layout(gtx)

	})
	a := clip.Rect(image.Rectangle{Max: dims.Size})
	t := a.Push(gtx.Ops)
	i.clicked.Add(gtx.Ops)
	t.Pop()
	return dims
}

func (i *Invoice) get() {
	i.Lock()
	amount := i.amount
	i.Unlock()
	invoice_request := cashu.InvoiceRequest{Amount: amount}
	resp, err := cwallet.CreateInvoice(invoice_request)
	if err != nil {
		log.Print(err)
	} else {
		i.Lock()
		i.paymentRequest = resp.PaymentRequest
		i.Unlock()
	}
}

func (i *Invoice) update(gtx layout.Context) {
	// request a new invoice if clicked
	for _, e := range i.clicked.Events(gtx.Queue) {
		if e.Type == gesture.TypeClick {
			go i.get()
			break
		}
	}
	// update the invoice amount from the editor
	for _, e := range i.amountEd.Events() {
		switch e.(type) {
		case widget.SubmitEvent:
			x := int64(0)
			_, err := fmt.Sscanf(i.amountEd.Text(), "%d", &x)
			if err == nil {
				i.Lock()
				i.amount = x
				i.Unlock()
				go i.get()
				break
			}
		}
	}
}

// Layout a QR code representing a lightning invoice for the topup amount
func (i *Invoice) Layout(gtx C) D {
	return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceBetween, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(material.H6(th, "Get Nuts: ").Layout),
					layout.Rigid(material.Editor(th, i.amountEd, "").Layout),
				)
			})
		}),
		layout.Flexed(.2, i.layoutQr), // hide/expand QR
		//layout.Rigid(material.H6(th, fmt.Sprintf("Amount: %v", i.invoice.Amount)).Layout),
		//layout.Rigid(material.H6(th, fmt.Sprintf("Paid: %v", i.invoice.Paid)).Layout),
	)
}

// Wallet is a widget that holds the current balance of nuts
type Wallet struct {
	balance int
	sync.Mutex
}

// Balance returns the remaining nuts
func (w *Wallet) Balance() int {
	w.Lock()
	defer w.Unlock()
	return w.balance
}

func (w *Wallet) update() {
	w.Lock()
	defer w.Unlock()
	balance, err := cwallet.GetBalance()
	if err == nil {
		log.Printf("got balance %d", balance.Balance)
		w.balance = balance.Balance

	} else {
		log.Print(err)
	}
}

// Layout renders the wallet balance
func (w *Wallet) Layout(gtx C) D {
	return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(material.H6(th, "Balance: ").Layout),
			layout.Rigid(material.H6(th, fmt.Sprintf("%d", w.Balance())).Layout),
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
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(material.H6(th, "SOCKS5 Port: ").Layout),
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

	// fetch an inital invoice
	go func() {
		invoice.get()
		a.w.Invalidate()
	}()

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
		a.Update(gtx)
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
func (a *App) Update(gtx layout.Context) {
	log.Print("Update")
	portSelect.Update()
	invoice.update(gtx)
	connectSwitch.update(a)
}

func (c *ConnectSwitch) update(a *App) {
	c.Lock()
	defer c.Unlock()
	if c.connected.Changed() {
		go a.doConnectClick()
	}
}

// This is the main app layout
func (a *App) Layout(gtx C) {
	// display connected status
	// display disconnect/connect button
	layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceBetween, Alignment: layout.Start}.Layout(gtx,
		// Proxy Port Selector
		layout.Rigid(portSelect.Layout),
		// layout the exit node selection
		//layout.Rigid(exitSelect.Layout),
		layout.Rigid(connectSwitch.Layout),
		// layout add credit topup invoice
		layout.Rigid(invoice.Layout),
		// wallet balance
		layout.Rigid(wallet.Layout),
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
			connectSwitch.Off()
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
			connectSwitch.Off()
			a.Unlock()
		})
	})
}

func main() {
	flag.IntVar(&invoiceAmount, "a", 42, "Amount of Cashu to make a lightning invoice for")
	flag.Parse()
	invoice.amountEd.SetText(fmt.Sprintf("%d", invoiceAmount))
	portSelect.Editor.SetText(fmt.Sprintf("%d", *socksPort))
	if *cli {
		c, err := setupClient()
		if err != nil {
			log.Fatal(err)
		}
		a := &App{
			c:           c,
			clicked:     make(chan struct{}, 2),
			connect:     &widget.Clickable{},
			connectOnce: new(sync.Once),
		}

		go a.doConnectClick()
		a.Wait()
		return
	}
	go func() {
		w := app.NewWindow(
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
