package main

import (
	"fmt"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"gioui.org/x/component"
	"unicode"
)

// SettingsPage is for user settings
type SettingsPage struct {
	back          *widget.Clickable
	useTor        *widget.Editor
	eraseMessages *widget.Editor
	submit        *widget.Clickable
}

var (
	inset              = layout.UniformInset(unit.Dp(8))
	inputAlignment     layout.Alignment
	switchUseTor       widget.Bool
	inputEraseMessages component.TextField
)

const (
	settingNameColumnWidth    = .3
	settingDetailsColumnWidth = 1 - settingNameColumnWidth
)

// Layout returns a simple centered layout prompting to update settings
func (p *SettingsPage) Layout(gtx layout.Context) layout.Dimensions {
	bg := Background{
		Color: th.Bg,
		Inset: layout.Inset{},
	}

	return bg.Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical, Alignment: layout.End}.Layout(gtx,
			// topbar
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Baseline}.Layout(gtx,
					layout.Rigid(material.Button(th, p.back, "<").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout),
					layout.Rigid(material.H6(th, "Settings").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout))
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(settingNameColumnWidth, func(gtx C) D {
						return inset.Layout(gtx, material.Body1(th, "Use Tor").Layout)
					}),
					layout.Flexed(settingDetailsColumnWidth, func(gtx C) D {
						if switchUseTor.Changed() {
							if switchUseTor.Value {
								fmt.Println("SETTING: Use Tor")
							} else {
								fmt.Println("SETTING: Do NOT use Tor")
							}
						}
						return inset.Layout(gtx, material.Switch(th, &switchUseTor).Layout)
					}),
				)
			}),
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(settingNameColumnWidth, func(gtx C) D {
						return inset.Layout(gtx, material.Body1(th, "Erase Messages After").Layout)
					}),
					layout.Flexed(settingDetailsColumnWidth, func(gtx C) D {
						if err := func() string {
							for _, r := range inputEraseMessages.Text() {
								if !unicode.IsDigit(r) {
									return "Must contain only single digits"
								}
							}
							return ""
						}(); err != "" {
							inputEraseMessages.SetError(err)
						} else {
							inputEraseMessages.ClearError()
						}
						inputEraseMessages.SingleLine = true
						inputEraseMessages.Alignment = inputAlignment
						return inputEraseMessages.Layout(gtx, th, "Days")
					}),
				)
			}),
			layout.Rigid(func(gtx C) D {
				return material.Button(th, p.submit, "MEOW").Layout(gtx)
			}),
		)
	})
}

// Event catches the widget submit events and calls Settings
func (p *SettingsPage) Event(gtx layout.Context) interface{} {
	if p.back.Clicked() {
		return BackEvent{}
	}
	return nil
}

func (p *SettingsPage) Start(stop <-chan struct{}) {
}

func newSettingsPage() *SettingsPage {
	p := &SettingsPage{}
	p.back = &widget.Clickable{}
	p.useTor = &widget.Editor{SingleLine: true, Submit: true}
	p.eraseMessages = &widget.Editor{SingleLine: true, Submit: true}
	p.submit = &widget.Clickable{}
	return p
}
