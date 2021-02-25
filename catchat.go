package main

import (
	"flag"
	"fmt"
	"image"
	"math"
	"os"
	"sort"
	"syscall"
	"time"

	"github.com/katzenpost/catshadow"
	catconfig "github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	clientConfig "github.com/katzenpost/client/config"

	"gioui.org/app"
	"image/color"
	//"gioui.org/io/event" // XXX what is here
	"gioui.org/font/gofont"
	//"gioui.org/io/key"
	//"gioui.org/io/pointer"
	"gioui.org/f32"
	"gioui.org/io/key"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material" // XXX what is here
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

	// disconnect, etc widget
	networkActionsBtn = new(widget.Clickable)

	// ui layout elements
	chatWho      string
	lastMessages = make(map[string]*catshadow.Message)

	// theme
	th = material.NewTheme(gofont.Collection())

	// status vars
	loggedIn  bool
	connected bool
	errStatus string
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

type pageStack struct {
	pages    []Page
	stopChan chan<- struct{}
}

type Page interface {
	Start(stop <-chan struct{})
	Event(gtx layout.Context) interface{}
	Layout(gtx layout.Context) layout.Dimensions
}

type Background struct {
	Color  color.NRGBA
	Radius unit.Value
	Inset  layout.Inset
}

type clipCircle struct {
}

func (cc *clipCircle) Layout(gtx layout.Context, w layout.Widget) layout.Dimensions {
	macro := op.Record(gtx.Ops)
	dims := w(gtx)
	call := macro.Stop()
	max := dims.Size.X
	if dy := dims.Size.Y; dy > max {
		max = dy
	}
	szf := float32(max)
	rr := szf * .5
	defer op.Save(gtx.Ops).Load()
	clip.RRect{
		Rect: f32.Rectangle{Max: f32.Point{X: szf, Y: szf}},
		NE:   rr, NW: rr, SE: rr, SW: rr,
	}.Add(gtx.Ops)
	call.Add(gtx.Ops)
	return dims
}

func (b *Background) Layout(gtx layout.Context, w layout.Widget) layout.Dimensions {
	macro := op.Record(gtx.Ops)
	dims := b.Inset.Layout(gtx, w)
	call := macro.Stop()
	defer op.Save(gtx.Ops).Load()
	size := dims.Size
	width, height := float32(size.X), float32(size.Y)
	if r := float32(gtx.Px(b.Radius)); r > 0 {
		if r > width/2 {
			r = width / 2
		}
		if r > height/2 {
			r = height / 2
		}
		clip.RRect{
			Rect: f32.Rectangle{Max: f32.Point{
				X: width, Y: height,
			}}, NW: r, NE: r, SW: r, SE: r,
		}.Add(gtx.Ops)
	}
	paint.FillShape(gtx.Ops, b.Color, clip.Rect(image.Rectangle{Max: size}).Op())
	call.Add(gtx.Ops)
	return dims
}

type Transition struct {
	prev, page Page
	reverse    bool
	time       time.Time
}

type BackEvent struct{}

type fill struct {
	color color.NRGBA
}

type icon struct {
	src  []byte
	size unit.Value

	// Cached values.
	op      paint.ImageOp
	imgSize int
}

func rgb(c uint32) color.NRGBA {
	return argb((0xff << 24) | c)
}

func argb(c uint32) color.NRGBA {
	return color.NRGBA{A: uint8(c >> 24), R: uint8(c >> 16), G: uint8(c >> 8), B: uint8(c)}
}

func (f fill) Layout(gtx layout.Context) layout.Dimensions {
	cs := gtx.Constraints
	d := cs.Min
	paint.FillShape(gtx.Ops, f.color, clip.Rect(image.Rectangle{Max: d}).Op())
	return layout.Dimensions{Size: d, Baseline: d.Y}
}

func (t *Transition) Start(stop <-chan struct{}) {
	t.page.Start(stop)
}

func (t *Transition) Event(gtx layout.Context) interface{} {
	return t.page.Event(gtx)
}

func (t *Transition) Layout(gtx layout.Context) layout.Dimensions {
	defer op.Save(gtx.Ops).Load()
	prev, page := t.prev, t.page
	if prev != nil {
		if t.reverse {
			prev, page = page, prev
		}
		now := gtx.Now
		if t.time.IsZero() {
			t.time = now
		}
		prev.Layout(gtx)
		cs := gtx.Constraints
		size := layout.FPt(cs.Max)
		max := float32(math.Sqrt(float64(size.X*size.X + size.Y*size.Y)))
		progress := float32(now.Sub(t.time).Seconds()) * 3
		progress = progress * progress // Accelerate
		if progress >= 1 {
			// Stop animation when complete.
			t.prev = nil
		}
		if t.reverse {
			progress = 1 - progress
		}
		diameter := progress * max
		radius := diameter / 2
		op.InvalidateOp{}.Add(gtx.Ops)
		center := size.Mul(.5)
		clipCenter := f32.Point{X: diameter / 2, Y: diameter / 2}
		off := f32.Affine2D{}.Offset(center.Sub(clipCenter))
		op.Affine(off).Add(gtx.Ops)
		clip.RRect{
			Rect: f32.Rectangle{Max: f32.Point{X: diameter, Y: diameter}},
			NE:   radius, NW: radius, SE: radius, SW: radius,
		}.Add(gtx.Ops)
		op.Affine(off.Invert()).Add(gtx.Ops)
		fill{rgb(0xffffff)}.Layout(gtx)
	}
	return page.Layout(gtx)
}

func (s *pageStack) Len() int {
	return len(s.pages)
}

func (s *pageStack) Current() Page {
	return s.pages[len(s.pages)-1]
}

func (s *pageStack) Pop() {
	s.stop()
	i := len(s.pages) - 1
	prev := s.pages[i]
	s.pages[i] = nil
	s.pages = s.pages[:i]
	if len(s.pages) > 0 {
		s.pages[i-1] = &Transition{
			reverse: true,
			prev:    prev,
			page:    s.Current(),
		}
		s.start()
	}
}

func (s *pageStack) start() {
	stop := make(chan struct{})
	s.stopChan = stop
	s.Current().Start(stop)
}

func (s *pageStack) Swap(p Page) {
	prev := s.pages[len(s.pages)-1]
	s.pages[len(s.pages)-1] = &Transition{
		prev: prev,
		page: p,
	}
	s.start()
}

func (s *pageStack) Push(p Page) {
	if s.stopChan != nil {
		s.stop()
	}
	if len(s.pages) > 0 {
		p = &Transition{
			prev: s.Current(),
			page: p,
		}
	}
	s.pages = append(s.pages, p)
	s.start()
}

func (s *pageStack) stop() {
	close(s.stopChan)
	s.stopChan = nil
}

func (s *pageStack) Clear(p Page) {
	for len(s.pages) > 0 {
		s.Pop()
	}
	s.Push(p)
}

type App struct {
	w      *app.Window
	client *catshadow.Client
	stack  pageStack
}

func newApp(w *app.Window) *App {
	a := &App{
		w: w,
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
		case SignInEvent:
			a.stack.Clear(newHomePage())
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
	var ops op.Ops
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
					connected = true
					status = "Connected"
					// emit some notification event
				} else {
					connected = false
					status = "Disconnected"
				}
				if event.Err != nil {
					errStatus = event.Err.Error()
					// emit some error efvent
				}
			case *catshadow.KeyExchangeCompletedEvent:

				// emit some notification event
				//event.Nickname, event.Err
				if event.Err != nil {
					errStatus = fmt.Sprintf("Key exchange failure with %s, %s", event.Nickname, event.Err.Error())
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
				errStatus = fmt.Sprintf("Message not sent to %s", event.Nickname)
			case *catshadow.MessageDeliveredEvent:
				// the status will be updated next frame
			case *catshadow.MessageReceivedEvent:
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
				gtx := layout.NewContext(&ops, e)
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
		a.w.Invalidate()
	}
}

type signInPage struct {
	password *widget.Editor
	submit   *widget.Clickable
}

func (p *signInPage) Start(stop <-chan struct{}) {
}

func (p *signInPage) Layout(gtx layout.Context) layout.Dimensions {
	p.password.Focus()
	return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
		layout.Flexed(1, func(gtx C) D {
			return material.Button(th, p.submit, "MEOW").Layout(gtx)
		}),
		layout.Flexed(1, func(gtx C) D {
			fill{rgb(0xefefef)}.Layout(gtx)
			return layout.Center.Layout(gtx, material.Editor(th, p.password, "Enter your password").Layout)
		}),
	)
}

type SignInEvent struct {
}

func (p *signInPage) Event(gtx layout.Context) interface{} {
	for _, ev := range p.password.Events() {
		switch ev.(type) {
		case widget.SubmitEvent:
			p.submit.Click()
		}
	}

	if p.submit.Clicked() {
		pw := p.password.Text()
		p.password.SetText("")
		if len(pw) != 0 && len(pw) < minPasswordLen {
		} else {
			started := make(chan interface{})
			go setupCatShadow(catshadowCfg, []byte(pw), started)
			// blocks UX
			<-started
			return SignInEvent{}
		}
	}
	return nil
}

func newSignInPage() *signInPage {
	return &signInPage{
		password: &widget.Editor{SingleLine: true, Mask: '*', Submit: true},
		submit:   &widget.Clickable{},
	}
}

type HomePage struct {
	addContact    *widget.Clickable
	contactClicks map[string]*widget.Clickable
}

type AddContactClick struct{}

func (p *HomePage) Layout(gtx layout.Context) layout.Dimensions {
	contacts := getSortedContacts()
	// xxx do not request this every frame...
	bg := Background{
		Color: th.ContrastBg,
		Inset: layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)},
	}
	return bg.Layout(gtx, func(gtx C) D {
		// returns a flex consisting of the contacts list and add contact button
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.Baseline, Spacing: layout.SpaceAround}.Layout(gtx,
			layout.Flexed(1, func(gtx C) D {
				gtx.Constraints.Min.X = gtx.Px(unit.Dp(200))
				// the contactList
				return contactList.Layout(gtx, len(contacts), func(gtx C, i int) layout.Dimensions {
					msgs := catshadowClient.GetSortedConversation(contacts[i])

					lastMsg := ""
					if len(msgs) > 0 {
						lastMsg = string(msgs[len(msgs)-1].Plaintext)
					}

					if _, ok := p.contactClicks[contacts[i]]; !ok {
						p.contactClicks[contacts[i]] = new(widget.Clickable)
					}
					// make the item a clickable
					return material.Clickable(gtx, p.contactClicks[contacts[i]], func(gtx C) D {
						// inset each contact Flex
						in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
						return in.Layout(gtx, func(gtx C) D {
							// returns Flex of contact icon, contact name, and last message received or sent
							return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceEvenly}.Layout(gtx,
								// contact icon
								layout.Rigid(func(gtx C) D {
									cc := clipCircle{}
									return cc.Layout(gtx, func(gtx C) D {
										sz := image.Point{X: gtx.Px(unit.Dp(96)), Y: gtx.Px(unit.Dp(96))}
										gtx.Constraints = layout.Exact(gtx.Constraints.Constrain(sz))
										return fill{th.Bg}.Layout(gtx)
									})
								}), // end contact icon
								// contact name and last message
								layout.Flexed(1, func(gtx C) D {
									return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceBetween}.Layout(gtx,
										// contact name
										layout.Rigid(func(gtx C) D {
											in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
											return in.Layout(gtx, material.Caption(th, contacts[i]).Layout)
										}),
										// last message
										layout.Rigid(func(gtx C) D {
											in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
											return in.Layout(gtx, func(gtx C) D {
												// TODO: set the color based on sent or received
												return material.Body2(th, lastMsg).Layout(gtx)
											})
										}),
									)
								}),
							)
						})
					})
				})
			}),
			// addContact
			layout.Rigid(func(gtx C) D {
				return layout.Center.Layout(gtx, material.Button(th, p.addContact, "Add Contact").Layout)
			}),
		)
	})
}

// ChooseContactClick is the event that indicates which contact was selected
type ChooseContactClick struct {
	nickname string
}

// Event returns a ChooseContactClick event when a contact is chosen
func (p *HomePage) Event(gtx layout.Context) interface{} {
	if p.addContact.Clicked() {
		return AddContactClick{}
	}
	for nickname, click := range p.contactClicks {
		if click.Clicked() {
			return ChooseContactClick{nickname: nickname}
		}
	}
	return nil
}

func (p *HomePage) Start(stop <-chan struct{}) {
}

func newHomePage() *HomePage {
	return &HomePage{
		addContact:    &widget.Clickable{},
		contactClicks: make(map[string]*widget.Clickable),
	}
}

// AddContactComplete is emitted when catshadow.NewContact has been called
type AddContactComplete struct {
	nickname string
}

// AddContactPage is the page for adding a new contact
type AddContactPage struct {
	nickname *widget.Editor
	secret   *widget.Editor
	submit   *widget.Clickable
}

// Layout returns a simple centered layout prompting user for contact nickname and secret
func (p *AddContactPage) Layout(gtx layout.Context) layout.Dimensions {
	return layout.Center.Layout(gtx, func(gtx C) D {
		return layout.Flex{Alignment: layout.Middle, Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx C) D { return layout.Center.Layout(gtx, material.Editor(th, p.nickname, "nickname").Layout) }),
			layout.Rigid(func(gtx C) D { return layout.Center.Layout(gtx, material.Editor(th, p.secret, "secret").Layout) }),
			layout.Rigid(func(gtx C) D { return layout.Center.Layout(gtx, material.Button(th, p.submit, "MEOW").Layout) }),
		)
	})
}

// Event catches the widget submit events and calls catshadow.NewContact
func (p *AddContactPage) Event(gtx layout.Context) interface{} {
	for _, ev := range p.nickname.Events() {
		switch ev.(type) {
		case widget.SubmitEvent:
			p.secret.Focus()
		}
	}
	for _, ev := range p.secret.Events() {
		switch ev.(type) {
		case widget.SubmitEvent:
			p.submit.Click()
		}
	}
	if p.submit.Clicked() {
		if len(p.secret.Text()) < minPasswordLen {
			p.secret.SetText("")
			p.secret.Focus()
			return nil
		}
		catshadowClient.NewContact(p.nickname.Text(), []byte(p.secret.Text()))
		return AddContactComplete{nickname: p.nickname.Text()}
	}
	return nil
}

func (p *AddContactPage) Start(stop <-chan struct{}) {
}

func newAddContactPage() *AddContactPage {
	p := &AddContactPage{}
	p.nickname = &widget.Editor{SingleLine: true, Submit: true}
	p.nickname.Focus()
	p.secret = &widget.Editor{SingleLine: true, Submit: true, Mask: '*'}
	p.submit = &widget.Clickable{}
	return p
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
			app.Size(unit.Dp(400), unit.Dp(800)),
			app.Title("Catchat"),
		)
		if err := newApp(w).run(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
		}

		if catshadowClient != nil {
			catshadowClient.Shutdown()
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

func (c *conversationPage) Layout(gtx layout.Context) layout.Dimensions {
	messages := catshadowClient.GetSortedConversation(c.nickname)
	c.compose.Focus()
	bgl := Background{
		Color: th.ContrastBg,
		Inset: layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)},
	}

	return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceAround, Alignment: layout.Baseline}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			in := layout.UniformInset(unit.Dp(8))
			return in.Layout(gtx, func(gtx C) D { return layout.Center.Layout(gtx, material.Caption(th, c.nickname).Layout) })
		}),
		layout.Flexed(3, func(gtx C) D {
			return bgl.Layout(gtx, func(ctx C) D {
				return messageList.Layout(gtx, len(messages), func(gtx C, i int) layout.Dimensions {
					bg := Background{
						Color:  th.ContrastFg,
						Inset:  layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)},
						Radius: unit.Dp(10),
					}
					if messages[i].Outbound {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline, Spacing: layout.SpaceAround}.Layout(gtx,
							layout.Flexed(1, fill{th.Fg}.Layout),
							layout.Flexed(1, func(gtx C) D {
								return bg.Layout(gtx, material.Body2(th, string(messages[i].Plaintext)).Layout)
							}),
						)
					} else {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline, Spacing: layout.SpaceAround}.Layout(gtx,
							layout.Flexed(1, func(gtx C) D {
								return bg.Layout(gtx, material.Body2(th, string(messages[i].Plaintext)).Layout)
							}),
							layout.Flexed(1, fill{th.Fg}.Layout),
						)
					}
				})
			})
		}),
		layout.Rigid(func(gtx C) D {
			bg := Background{
				Color: th.ContrastFg,
				Inset: layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(20), Left: unit.Dp(12), Right: unit.Dp(12)},
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
