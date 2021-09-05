package main

import (
	"bytes"
	"encoding/base64"
	"gioui.org/gesture"
	"gioui.org/io/clipboard"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/benc-uk/gofract/pkg/colors"
	"github.com/benc-uk/gofract/pkg/fractals"
	"github.com/katzenpost/katzenpost/catshadow"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/exp/shiny/materialdesign/icons"
	"image"
	"image/png"
	mrand "math/rand"
	"runtime"
	"sort"
)

// AddContactComplete is emitted when catshadow.NewContact has been called
type AddContactComplete struct {
	nickname string
}

var (
	copyIcon, _   = widget.NewIcon(icons.ContentContentCopy)
	pasteIcon, _  = widget.NewIcon(icons.ContentContentPaste)
	submitIcon, _ = widget.NewIcon(icons.NavigationCheck)
	cancelIcon, _ = widget.NewIcon(icons.NavigationCancel)
)

// AddContactPage is the page for adding a new contact
type AddContactPage struct {
	a         *App
	nickname  *widget.Editor
	avatar    *widget.Image
	palette   colors.GradientTable
	copy      *widget.Clickable
	paste     *widget.Clickable
	back      *widget.Clickable
	newAvatar *gesture.Click
	newQr     *gesture.Click
	secret    *widget.Editor
	submit    *widget.Clickable
	cancel    *widget.Clickable
	qr        *widget.Image
	x, y      float64
	xx, yy    float64
}

// Layout returns a simple centered layout prompting user for contact nickname and secret
func (p *AddContactPage) Layout(gtx layout.Context) layout.Dimensions {
	bg := Background{
		Color: th.Bg,
		Inset: layout.Inset{},
	}

	return bg.Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.End}.Layout(gtx,
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Baseline}.Layout(gtx,
					layout.Rigid(button(th, p.back, backIcon).Layout),
					layout.Flexed(1, fill{th.Bg}.Layout),
					layout.Rigid(material.H6(th, "Add Contact").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout))
			}),
			// Nickname and Avatar image
			layout.Flexed(1, func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Flexed(1, func(gtx C) D {
						return layout.Center.Layout(gtx, material.Editor(th, p.nickname, "Nickname").Layout)
					}),
					layout.Flexed(1, func(gtx C) D {
						return layout.Center.Layout(gtx, p.layoutAvatar)
					}),
				)
			}),
			// secret entry and QR image
			layout.Flexed(1, func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Flexed(1, func(gtx C) D {
						// vertical secret and copy/paste controls beneath
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							// secret string
							layout.Flexed(1, func(gtx C) D {
								in := layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8), Top: unit.Dp(8), Bottom: unit.Dp(8)}
								return in.Layout(gtx, func(gtx C) D {
									return layout.Center.Layout(gtx, material.Editor(th, p.secret, "Secret").Layout)
								})
							}),
							// copy/paste
							layout.Rigid(func(gtx C) D {
								return layout.Center.Layout(gtx, func(gtx C) D {
									return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.End}.Layout(gtx,
										layout.Flexed(1, button(th, p.copy, copyIcon).Layout),
										layout.Flexed(1, button(th, p.paste, pasteIcon).Layout),
										layout.Flexed(1, button(th, p.submit, submitIcon).Layout),
										layout.Flexed(1, button(th, p.cancel, cancelIcon).Layout),
									)
								})
							}),
						)
					}),
					// the image widget of qrcode
					layout.Flexed(1, func(gtx C) D {
						return layout.Center.Layout(gtx, p.layoutQr)
					}),
				)
			}),
		)
	})
}

// Event catches the widget submit events and calls catshadow.NewContact
func (p *AddContactPage) Event(gtx layout.Context) interface{} {
	if p.back.Clicked() {
		return BackEvent{}
	}
	for _, ev := range p.nickname.Events() {
		switch ev.(type) {
		case widget.SubmitEvent:
			p.secret.Focus()
		}
	}

	for _, e := range p.newQr.Events(gtx.Queue) {
		if e.Type == gesture.TypeClick {
			p.qr = nil
			b := make([]byte, 32)
			rand.Reader.Read(b)
			p.secret.SetText(base64.StdEncoding.EncodeToString(b))
		}
	}

	if p.copy.Clicked() {
		clipboard.WriteOp{Text: p.secret.Text()}.Add(gtx.Ops)
		return nil
	}

	if p.paste.Clicked() {
		clipboard.ReadOp{Tag: p}.Add(gtx.Ops)
	}

	for _, e := range gtx.Events(p) {
		ce := e.(clipboard.Event)
		p.secret.SetText(ce.Text)
	}

	for _, e := range p.newAvatar.Events(gtx.Queue) {
		if e.Type == gesture.TypeClick {
			p.avatar = nil
			p.palette.Randomise()
			p.xx = mrand.Float64()
			p.x = mrand.Float64()
			p.y = mrand.Float64()
			p.yy = mrand.Float64()
		}
	}

	for _, ev := range p.secret.Events() {
		switch ev.(type) {
		case widget.SubmitEvent:
			p.submit.Click()
		}
	}
	if p.cancel.Clicked() {
		return BackEvent{}
	}
	if p.submit.Clicked() {
		if len(p.secret.Text()) < minPasswordLen {
			p.secret.SetText("")
			p.secret.Focus()
			return nil
		}

		if len(p.nickname.Text()) == 0 {
			p.nickname.Focus()
			return nil
		}

		p.a.c.NewContact(p.nickname.Text(), []byte(p.secret.Text()))
		b := &bytes.Buffer{}
		sz := image.Point{X: gtx.Px(unit.Dp(96)), Y: gtx.Px(unit.Dp(96))}
		i := image.NewRGBA(image.Rectangle{Max: sz})
		f := p.fractal(sz)
		f.Render(i, p.palette)

		if err := png.Encode(b, i); err == nil {
			p.a.c.AddBlob("avatar://"+p.nickname.Text(), b.Bytes())
		}
		return AddContactComplete{nickname: p.nickname.Text()}
	}
	return nil
}

func (p *AddContactPage) Start(stop <-chan struct{}) {
}

func newAddContactPage(a *App) *AddContactPage {
	p := &AddContactPage{}
	p.a = a
	p.nickname = &widget.Editor{SingleLine: true, Submit: true}
	p.secret = &widget.Editor{SingleLine: false, Submit: true}
	if runtime.GOOS == "android" {
		p.secret.Submit = false
	}

	// avatar parameters
	p.xx = mrand.Float64()
	p.yy = mrand.Float64()
	p.palette = colors.GradientTable{}
	p.palette.Randomise()

	p.newAvatar = new(gesture.Click)
	p.newQr = new(gesture.Click)
	p.back = &widget.Clickable{}
	p.copy = &widget.Clickable{}
	p.paste = &widget.Clickable{}
	p.submit = &widget.Clickable{}
	p.cancel = &widget.Clickable{}

	p.nickname.Focus()
	return p
}

func (p *AddContactPage) fractal(sz image.Point) *fractals.Fractal {
	return &fractals.Fractal{FractType: "julia",
		Center:       fractals.ComplexPair{p.x, p.y},
		MagFactor:    1.0,
		MaxIter:      90,
		W:            1.0,
		H:            1.0,
		ImgWidth:     sz.X,
		JuliaSeed:    fractals.ComplexPair{p.xx, p.yy},
		InnerColor:   "#000000",
		FullScreen:   false,
		ColorRepeats: 2.0}
}

func (p *AddContactPage) layoutQr(gtx C) D {
	in := layout.Inset{}
	dims := in.Layout(gtx, func(gtx C) D {
		x := gtx.Constraints.Max.X
		y := gtx.Constraints.Max.Y
		if x > y {
			x = y
		}

		sz := image.Point{X: x, Y: x}
		gtx.Constraints = layout.Exact(gtx.Constraints.Constrain(sz))
		qr, err := qrcode.New(p.secret.Text(), qrcode.High)
		if err != nil {
			return layout.Center.Layout(gtx, material.Caption(th, "QR").Layout)
		}
		qr.BackgroundColor = th.Bg
		qr.ForegroundColor = th.Fg

		i := qr.Image(x)
		return widget.Image{Fit: widget.ScaleDown, Src: paint.NewImageOp(i)}.Layout(gtx)

	})
	a := pointer.Rect(image.Rectangle{Max: dims.Size})
	a.Add(gtx.Ops)
	p.newQr.Add(gtx.Ops)
	return dims

}
func (p *AddContactPage) layoutAvatar(gtx C) D {
	in := layout.Inset{}
	cc := clipCircle{}

	return in.Layout(gtx, func(gtx C) D {
		dims := cc.Layout(gtx, func(gtx C) D {
			x := gtx.Constraints.Max.X
			y := gtx.Constraints.Max.Y
			if x > y {
				x = y
			}
			sz := image.Point{X: x, Y: x}

			gtx.Constraints = layout.Exact(gtx.Constraints.Constrain(sz))
			f := p.fractal(sz)

			i := image.NewRGBA(image.Rectangle{Max: sz})
			f.Render(i, p.palette)
			return widget.Image{Scale: float32(1), Src: paint.NewImageOp(i)}.Layout(gtx)

		})
		a := pointer.Rect(image.Rectangle{Max: dims.Size})
		a.Add(gtx.Ops)
		p.newAvatar.Add(gtx.Ops)
		return dims
	})
}

type sortedContacts []*catshadow.Contact

func (s sortedContacts) Less(i, j int) bool {
	// sorts contacts with messages most-recent-first, followed by contacts
	// without messages alphabetically
	if s[i].LastMessage == nil && s[j].LastMessage == nil {
		return s[i].Nickname < s[j].Nickname
	} else if s[i].LastMessage == nil {
		return false
	} else if s[j].LastMessage == nil {
		return true
	} else {
		return s[i].LastMessage.Timestamp.After(s[j].LastMessage.Timestamp)
	}
}
func (s sortedContacts) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s sortedContacts) Len() int {
	return len(s)
}

func getSortedContacts(a *App) (contacts sortedContacts) {
	if a.c == nil {
		return
	}

	// returns map[string]*Contact
	for _, contact := range a.c.GetContacts() {
		contacts = append(contacts, contact)
	}
	sort.Sort(contacts)
	return
}

func button(th *material.Theme, button *widget.Clickable, icon *widget.Icon) material.IconButtonStyle {
	return material.IconButtonStyle{
		Background: th.Palette.Bg,
		Color:      th.Palette.ContrastFg,
		Icon:       icon,
		Size:       unit.Dp(20),
		Inset:      layout.UniformInset(unit.Dp(8)),
		Button:     button,
	}
}
