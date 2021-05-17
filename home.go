package main

import (
	"bytes"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/benc-uk/gofract/pkg/colors"
	"github.com/benc-uk/gofract/pkg/fractals"
	"github.com/hako/durafmt"
	"image"
	"image/png"
	"math/rand"
	"runtime"
	"strings"
	"time"
)

var (
	contactList = &layout.List{Axis: layout.Vertical, ScrollToEnd: false}
)

type HomePage struct {
	addContact    *widget.Clickable
	showSettings  *widget.Clickable
	av            map[string]*widget.Image
	contactClicks map[string]*Click
}

type AddContactClick struct{}
type ShowSettingsClick struct{}

func (p *HomePage) Layout(gtx layout.Context) layout.Dimensions {
	contacts := getSortedContacts()
	// xxx do not request this every frame...
	bg := Background{
		Color: th.Bg,
		Inset: layout.Inset{},
	}
	return bg.Layout(gtx, func(gtx C) D {
		// returns a flex consisting of the contacts list and add contact button
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.End}.Layout(gtx,
			// topbar: Name, Add Contact, Settings
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Baseline}.Layout(
					gtx,
					layout.Rigid(material.H6(th, "Home").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout),
					layout.Rigid(material.Button(th, p.addContact, "Add Contact").Layout),
					layout.Rigid(material.Button(th, p.showSettings, "Settings").Layout),
				)
			}),

			// show list of conversations
			layout.Flexed(1, func(gtx C) D {
				gtx.Constraints.Min.X = gtx.Px(unit.Dp(300))
				// the contactList
				return contactList.Layout(gtx, len(contacts), func(gtx C, i int) layout.Dimensions {
					lastMsg := contacts[i].LastMessage

					// inset each contact Flex
					in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
					return in.Layout(gtx, func(gtx C) D {
						// returns Flex of contact icon, contact name, and last message received or sent
						if _, ok := p.contactClicks[contacts[i].Nickname]; !ok {
							c := new(Click)
							p.contactClicks[contacts[i].Nickname] = c
						}

						dims := layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceEvenly}.Layout(gtx,
							// contact avatar
							layout.Rigid(func(gtx C) D {
								cc := clipCircle{}
								return cc.Layout(gtx, func(gtx C) D {
									sz := image.Point{X: gtx.Px(unit.Dp(96)), Y: gtx.Px(unit.Dp(96))}
									gtx.Constraints = layout.Exact(gtx.Constraints.Constrain(sz))
									return p.layoutAvatar(gtx, contacts[i].Nickname)
								})
							}), // end contact icon
							// contact name and last message
							layout.Flexed(1, func(gtx C) D {
								return layout.Flex{Axis: layout.Vertical, Alignment: layout.Start, Spacing: layout.SpaceBetween}.Layout(gtx,
									layout.Rigid(func(gtx C) D {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Start, Spacing: layout.SpaceBetween}.Layout(gtx,
											// contact name
											layout.Rigid(func(gtx C) D {
												in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
												return in.Layout(gtx, material.Caption(th, contacts[i].Nickname).Layout)
											}),
											layout.Rigid(func(gtx C) D {
												// timestamp
												if lastMsg != nil {
													messageAge := strings.Replace(durafmt.ParseShort(time.Now().Sub(lastMsg.Timestamp).Truncate(time.Minute)).String(), "0 seconds", "now", 1)
													return material.Caption(th, messageAge).Layout(gtx)
												}
												return fill{th.Bg}.Layout(gtx)
											}),
										)
									}),
									// last message
									layout.Rigid(func(gtx C) D {
										in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
										if lastMsg != nil {
											return in.Layout(gtx, func(gtx C) D {
												// TODO: set the color based on sent or received
												return material.Body2(th, string(lastMsg.Plaintext)).Layout(gtx)
											})
										} else {
											return fill{th.Bg}.Layout(gtx)
										}
									}),
								)
							}),
						)
						a := pointer.Rect(image.Rectangle{Max: dims.Size})
						a.Add(gtx.Ops)
						p.contactClicks[contacts[i].Nickname].Add(gtx.Ops)
						return dims
					})
				})
			}),
		)
	})
}

func (p *HomePage) layoutAvatar(gtx C, nickname string) D {
	cc := clipCircle{}
	return cc.Layout(gtx, func(gtx C) D {
		sz := image.Point{X: gtx.Px(unit.Dp(96)), Y: gtx.Px(unit.Dp(96))}
		gtx.Constraints = layout.Exact(gtx.Constraints.Constrain(sz))
		if cachedAv, ok := p.av[nickname]; ok {
			return cachedAv.Layout(gtx)
		}
		// render the saved avatar image, if present
		if b, err := catshadowClient.GetBlob("avatar://" + nickname); err == nil {
			if m, _, err := image.Decode(bytes.NewReader(b)); err == nil {
				scale := float32(sz.X) / float32(m.Bounds().Size().X)
				av := &widget.Image{Scale: scale, Src: paint.NewImageOp(m)}
				p.av[nickname] = av
				return av.Layout(gtx)
			} else {
				panic(err)
			}
		}
		// generate an avatar
		// complexPair JuliaSeed
		f := fractals.Fractal{FractType: "julia",
			Center: fractals.ComplexPair{rand.Float64(), rand.Float64()},
			//Center: fractals.ComplexPair{-0.6, 0.0},
			MagFactor: 1.0,
			MaxIter:   90,
			W:         3.0,
			H:         2.0,
			ImgWidth:  sz.X,
			JuliaSeed: fractals.ComplexPair{rand.Float64(), rand.Float64()},
			//JuliaSeed: fractals.ComplexPair{0.355, 0.355},
			InnerColor:   "#000000",
			FullScreen:   false,
			ColorRepeats: 2.0,
		}

		i := image.NewRGBA(image.Rectangle{Max: sz})
		palette := colors.GradientTable{}
		palette.Randomise()
		f.Render(i, palette)
		b := &bytes.Buffer{}
		if err := png.Encode(b, i); err == nil {
			catshadowClient.AddBlob("avatar://"+nickname, b.Bytes())
		}
		scale := 1.0
		av := &widget.Image{Scale: float32(scale), Src: paint.NewImageOp(i)}
		p.av[nickname] = av
		return av.Layout(gtx)
	})
}

// ChooseContactClick is the event that indicates which contact was selected
type ChooseContactClick struct {
	nickname string
}

// Event returns a ChooseContactClick event when a contact is chosen
func (p *HomePage) Event(gtx layout.Context) interface{} {
	// listen for pointer right click events on the addContact widget
	if p.addContact.Clicked() {
		return AddContactClick{}
	}
	if p.showSettings.Clicked() {
		return ShowSettingsClick{}
	}
	for nickname, click := range p.contactClicks {
		for _, e := range click.Events(gtx.Queue) {
			if e.Type == TypeClick {
				if e.Buttons.Contain(pointer.ButtonPrimary) {
					// do the left button click thing
					return ChooseContactClick{nickname: nickname}
				}
				if e.Buttons.Contain(pointer.ButtonSecondary) {
					return EditContact{nickname: nickname}
					// do the right button click thing
				}
				// does not set buttons? but why?
				if runtime.GOOS == "android" {
					return ChooseContactClick{nickname: nickname}
				}
			}
		}
	}
	return nil
}

func (p *HomePage) Start(stop <-chan struct{}) {
}

func newHomePage() *HomePage {
	return &HomePage{
		addContact:    &widget.Clickable{},
		showSettings:  &widget.Clickable{},
		contactClicks: make(map[string]*Click),
		av:            make(map[string]*widget.Image),
	}
}
