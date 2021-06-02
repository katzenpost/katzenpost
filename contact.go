package main

import (
	"bytes"
	"gioui.org/layout"
	"gioui.org/op/paint"
	"gioui.org/widget"
	"github.com/benc-uk/gofract/pkg/colors"
	"github.com/benc-uk/gofract/pkg/fractals"
	"image"
	"image/png"
	"math/rand"
	//"gioui.org/io/clipboard"
	"gioui.org/io/pointer"
	"gioui.org/unit"
	"gioui.org/widget/material"
	"github.com/katzenpost/catshadow"
	"runtime"
	"sort"
)

// AddContactComplete is emitted when catshadow.NewContact has been called
type AddContactComplete struct {
	nickname string
}

// AddContactPage is the page for adding a new contact
type AddContactPage struct {
	nickname  *widget.Editor
	avatar    *widget.Image
	palette   colors.GradientTable
	back      *widget.Clickable
	newAvatar *Click
	secret    *widget.Editor
	submit    *widget.Clickable
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
					layout.Rigid(material.Button(th, p.back, "<").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout),
					layout.Rigid(material.H6(th, "Add Contact").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout))
			}),
			layout.Flexed(1, func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Flexed(1, func(gtx C) D {
						return layout.Center.Layout(gtx, material.Editor(th, p.nickname, "Nickname").Layout)
					}),
					layout.Flexed(1, func(gtx C) D {
						return layout.Center.Layout(gtx, p.layoutAvatar)
					}))
			}),
			layout.Flexed(1, func(gtx C) D {
				return layout.Center.Layout(gtx, material.Editor(th, p.secret, "Secret").Layout)
			}),
			layout.Rigid(func(gtx C) D {
				return material.Button(th, p.submit, "MEOW").Layout(gtx)
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
	for _, e := range p.newAvatar.Events(gtx.Queue) {
		if e.Type == TypeClick {
			p.avatar = nil
			p.xx = rand.Float64()
			p.x = rand.Float64()
			p.y = rand.Float64()
			p.yy = rand.Float64()
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
		b := &bytes.Buffer{}
		sz := image.Point{X: gtx.Px(unit.Dp(96)), Y: gtx.Px(unit.Dp(96))}
		i := image.NewRGBA(image.Rectangle{Max: sz})
		f := p.fractal(sz)
		f.Render(i, p.palette)

		if err := png.Encode(b, i); err == nil {
			catshadowClient.AddBlob("avatar://"+p.nickname.Text(), b.Bytes())
		}
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
	p.back = &widget.Clickable{}

	p.xx = rand.Float64()
	p.yy = rand.Float64()
	p.palette = colors.GradientTable{}
	p.palette.Randomise()
	p.newAvatar = new(Click)
	p.secret = &widget.Editor{SingleLine: true, Submit: true}
	if runtime.GOOS == "android" {
		p.secret.Submit = false
	}
	p.submit = &widget.Clickable{}
	return p
}

func (p *AddContactPage) fractal(sz image.Point) *fractals.Fractal {
	return &fractals.Fractal{FractType: "julia",
		Center:       fractals.ComplexPair{p.x, p.y},
		MagFactor:    1.0,
		MaxIter:      90,
		W:            3.0,
		H:            2.0,
		ImgWidth:     sz.X,
		JuliaSeed:    fractals.ComplexPair{p.xx, p.yy},
		InnerColor:   "#000000",
		FullScreen:   false,
		ColorRepeats: 2.0}
}

func (p *AddContactPage) layoutAvatar(gtx C) D {
	scale := 1.0
	in := layout.Inset{Left: unit.Dp(0), Right: unit.Dp(0)}
	cc := clipCircle{}

	return in.Layout(gtx, func(gtx C) D {
		dims := cc.Layout(gtx, func(gtx C) D {
			y := gtx.Constraints.Max.Y / 2
			sz := image.Point{X: y, Y: y}

			gtx.Constraints = layout.Exact(gtx.Constraints.Constrain(sz))
			if p.avatar != nil {
				return p.avatar.Layout(gtx)
			}
			f := p.fractal(sz)

			i := image.NewRGBA(image.Rectangle{Max: sz})
			p.palette.Randomise()
			f.Render(i, p.palette)
			p.avatar = &widget.Image{Scale: float32(scale), Src: paint.NewImageOp(i)}
			return p.avatar.Layout(gtx)

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

func getSortedContacts() (contacts sortedContacts) {
	if catshadowClient == nil {
		return
	}

	// returns map[string]*Contact
	for _, contact := range catshadowClient.GetContacts() {
		contacts = append(contacts, contact)
	}
	sort.Sort(contacts)
	return
}
