package main

import (
	"gioui.org/layout"
	"gioui.org/io/pointer"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/katzenpost/catshadow"
	"image"
	"time"
)

var (
	contactList = &layout.List{Axis: layout.Vertical, ScrollToEnd: false}
)

type HomePage struct {
	addContact    *widget.Clickable
	contactClicks map[string]*Click
}

type AddContactClick struct{}

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
			layout.Flexed(1, func(gtx C) D {
				gtx.Constraints.Min.X = gtx.Px(unit.Dp(300))
				// the contactList
				return contactList.Layout(gtx, len(contacts), func(gtx C, i int) layout.Dimensions {
					msgs := catshadowClient.GetSortedConversation(contacts[i])

					var lastMsg *catshadow.Message
					if len(msgs) > 0 {
						lastMsg = msgs[len(msgs)-1]
					}

					// inset each contact Flex
					in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
					return in.Layout(gtx, func(gtx C) D {
						// returns Flex of contact icon, contact name, and last message received or sent
						if _, ok := p.contactClicks[contacts[i]]; !ok {
							c := new(Click)
							p.contactClicks[contacts[i]] = c
						}


						dims := layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceEvenly}.Layout(gtx,
							// contact icon
							layout.Rigid(func(gtx C) D {
								cc := clipCircle{}
								return cc.Layout(gtx, func(gtx C) D {
									sz := image.Point{X: gtx.Px(unit.Dp(96)), Y: gtx.Px(unit.Dp(96))}
									gtx.Constraints = layout.Exact(gtx.Constraints.Constrain(sz))
									return fill{th.ContrastBg}.Layout(gtx)
								})
							}), // end contact icon
							// contact name and last message
							layout.Flexed(1, func(gtx C) D {
								return layout.Flex{Axis: layout.Vertical, Alignment:layout.Start, Spacing: layout.SpaceBetween}.Layout(gtx,
									layout.Rigid(func(gtx C) D {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Start, Spacing: layout.SpaceBetween}.Layout(gtx,
										// contact name
										layout.Rigid(func(gtx C) D {
											in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
											return in.Layout(gtx, material.Caption(th, contacts[i]).Layout)
										}),
										layout.Rigid(func(gtx C) D {
											// timestamp
											if lastMsg != nil {
												messageAge := time.Now().Sub(lastMsg.Timestamp)
												messageAge = messageAge.Round(time.Minute)
												return material.Body2(th, messageAge.String()).Layout(gtx)
											}
											return fill{th.Bg}.Layout(gtx)
										}),
									)}),
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
						p.contactClicks[contacts[i]].Add(gtx.Ops)
						return dims
					})
				})
			}),
			// addContact
			layout.Rigid(func(gtx C) D {
				return material.Button(th, p.addContact, "Add Contact").Layout(gtx)
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
	// listen for pointer right click events on the addContact widget
	if p.addContact.Clicked() {
		return AddContactClick{}
	}
	for nickname, click := range p.contactClicks {
		for _, e := range click.Events(gtx.Queue) {
			if e.Type == TypeClick {
				if e.Buttons.Contain(pointer.ButtonLeft) {
					// do the left button click thing
					return ChooseContactClick{nickname: nickname}
				}
				if e.Buttons.Contain(pointer.ButtonRight) {
					return EditContact{nickname: nickname}
					// do the right button click thing
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
		contactClicks: make(map[string]*Click),
	}
}
