package main

import (
	"bytes"
	"gioui.org/app"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"golang.org/x/image/draw"
	"image"
	_ "image/jpeg"
	"image/png"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var (
	avatarPickerList = &layout.List{Axis: layout.Vertical}
)

type AvatarPicker struct {
	nickname string
	path     string
	back     *widget.Clickable
	clear    *widget.Clickable
	up       *widget.Clickable
	clicks   map[string]*Click
}

// AvatarSelected is the event that indicates a chosen avatar image
type AvatarSelected struct {
	nickname, path string
}

// AvatarCleared is the event that indicates avatars must be redrawn
type AvatarCleared struct {
	nickname string
}

// Layout displays a file chooser for supported image types
func (p *AvatarPicker) Layout(gtx layout.Context) layout.Dimensions {
	bg := Background{
		Color: th.Bg,
		Inset: layout.Inset{},
	}

	return bg.Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceBetween, Alignment: layout.Middle}.Layout(gtx,
			// back to Edit Contact
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline}.Layout(gtx,
					layout.Rigid(material.Button(th, p.back, "<").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout),
					layout.Rigid(material.H6(th, "Choose Avatar").Layout),
					layout.Flexed(1, fill{th.Bg}.Layout),
				)
			}),
			// cwd and buttons
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Baseline}.Layout(gtx,
					layout.Rigid(material.Button(th, p.up, "..").Layout),
					layout.Rigid(material.Button(th, p.clear, "Random").Layout),
					layout.Flexed(1, material.Body1(th, p.path).Layout),
				)
			}),
			// list contents
			layout.Flexed(1, func(gtx C) D {
				// get contents of directory at cwd
				files, err := ioutil.ReadDir(p.path)
				if err != nil {
					return material.Body2(th, "Unable to open path").Layout(gtx)
				}

				ff := make([]os.FileInfo, 0, len(files))
				// filter non image filesnames and hidden directories
				for _, fn := range files {
					n := strings.ToLower(fn.Name())
					// skip .paths
					if strings.HasPrefix(n, ".") {
						continue
					}
					if fn.IsDir() || strings.HasSuffix(n, ".jpg") || strings.HasSuffix(n, ".png") || strings.HasSuffix(n, ".jpeg") {
						ff = append(ff, fn)
					}
				}

				// file item layout
				return avatarPickerList.Layout(gtx, len(ff), func(gtx C, i int) D {
					fn := ff[i]
					if fn.IsDir() {
						// is a directory, attach clickable that will update the path if clicked...
						if _, ok := p.clicks[fn.Name()]; !ok {
							c := new(Click)
							p.clicks[fn.Name()] = c
						}
						in := layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
						dims := in.Layout(gtx, func(gtx C) D {
							return material.Body1(th, fn.Name()).Layout(gtx)
						})
						a := pointer.Rect(image.Rectangle{Max: dims.Size})
						a.Add(gtx.Ops)
						p.clicks[fn.Name()].Add(gtx.Ops)
						return dims

					} else {
						nfn := strings.ToLower(fn.Name())
						if strings.HasSuffix(nfn, ".png") || strings.HasSuffix(nfn, ".jpg") || strings.HasSuffix(nfn, ".jpeg") {
							if f, err := os.Open(filepath.Join(p.path, fn.Name())); err == nil {
								if m, _, err := image.Decode(f); err == nil {
									in := layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(12), Left: unit.Dp(12), Right: unit.Dp(12)}
									dims := in.Layout(gtx, func(gtx C) D {
										sz := m.Bounds().Size()
										scale := float32(gtx.Constraints.Max.X) / float32(sz.X)
										return widget.Image{Scale: scale, Src: paint.NewImageOp(m)}.Layout(gtx)
									})
									a := pointer.Rect(image.Rectangle{Max: dims.Size})
									a.Add(gtx.Ops)
									if _, ok := p.clicks[fn.Name()]; !ok {
										c := new(Click)
										p.clicks[fn.Name()] = c
									}
									p.clicks[fn.Name()].Add(gtx.Ops)
									return dims
								}
							}
						}
						return material.Body2(th, fn.Name()).Layout(gtx)
					}

				})
			}),
		)
	})
}

func (p *AvatarPicker) Event(gtx C) interface{} {
	if p.clear.Clicked() {
		clearAvatar(p.nickname)
		return AvatarCleared{nickname: p.nickname}
	}
	if p.up.Clicked() {
		if u, err := filepath.Abs(filepath.Join(p.path, "..")); err == nil {
			p.path = u
		}
		return nil
	}
	if p.back.Clicked() {
		return BackEvent{}
	}

	for filename, click := range p.clicks {
		for _, e := range click.Events(gtx.Queue) {
			if e.Type == TypeClick {
				// if it is a directory path - change the path
				// if it is a file path, return the file selection event
				if u, err := filepath.Abs(filepath.Join(p.path, filename)); err == nil {
					if f, err := os.Stat(u); err == nil {
						if f.IsDir() {
							p.path = u
						} else {
							return AvatarSelected{nickname: p.nickname, path: u}
						}
					}
				}
			}
		}
	}
	return nil
}

func (p *AvatarPicker) Start(stop <-chan struct{}) {
}

func newAvatarPicker(nickname string) *AvatarPicker {
	cwd, _ := app.DataDir() // XXX: select media/storage on android
	return &AvatarPicker{up: &widget.Clickable{},
		nickname: nickname,
		back:     &widget.Clickable{},
		clear:    &widget.Clickable{},
		clicks:   make(map[string]*Click),
		path:     cwd}
}

func scale(src image.Image, rect image.Rectangle, scale draw.Scaler) image.Image {
	dst := image.NewRGBA(rect)
	scale.Scale(dst, rect, src, src.Bounds(), draw.Over, nil)
	return dst
}

func clearAvatar(nickname string) {
	catshadowClient.DeleteBlob("avatar://" + nickname)
}

func setAvatar(nickname, path string) {
	if b, err := ioutil.ReadFile(path); err == nil {
		// scale file
		if m, _, err := image.Decode(bytes.NewReader(b)); err == nil {
			avatarSz := image.Rect(0, 0, 96, 96)
			resized := scale(m, avatarSz, draw.ApproxBiLinear)
			b := &bytes.Buffer{}
			if err := png.Encode(b, resized); err == nil {
				catshadowClient.AddBlob("avatar://"+nickname, b.Bytes())
			}
		}
	} else {
		panic(err)
	}
}
