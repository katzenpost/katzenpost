// SPDX-License-Identifier: AGPL-3.0-only

package logtest

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"regexp"
	"strconv"
	"testing"
)

var methods = map[string]bool{
	"Debug": true, "Debugf": true, "Info": true, "Infof": true, "Notice": true, "Noticef": true,
	"Warning": true, "Warningf": true, "Error": true, "Errorf": true,
}

var verb = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z%]`)

type Call struct {
	Pos    token.Position
	Method string
	Format string
	Args   []string
}

func Calls(t *testing.T, files ...string) []Call {
	t.Helper()
	fset := token.NewFileSet()
	var calls []Call
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !methods[sel.Sel.Name] {
				return true
			}
			recv, ok := sel.X.(*ast.SelectorExpr)
			if !ok || recv.Sel.Name != "log" {
				return true
			}
			c := Call{Pos: fset.Position(call.Pos()), Method: sel.Sel.Name}
			for i, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok && i == 0 && lit.Kind == token.STRING {
					c.Format, _ = strconv.Unquote(lit.Value)
					continue
				}
				var b bytes.Buffer
				if err := printer.Fprint(&b, fset, arg); err != nil {
					t.Fatal(err)
				}
				c.Args = append(c.Args, b.String())
			}
			calls = append(calls, c)
			return true
		})
	}
	return calls
}

func ArgsMatching(t *testing.T, identifier *regexp.Regexp, files ...string) []string {
	t.Helper()
	var found []string
	for _, c := range Calls(t, files...) {
		var verbs []string
		for _, v := range verb.FindAllString(c.Format, -1) {
			if v != "%%" {
				verbs = append(verbs, v)
			}
		}
		for i, arg := range c.Args {
			if i < len(verbs) && verbs[i] == "%T" {
				continue
			}
			if identifier.MatchString(arg) {
				found = append(found, c.Pos.String()+": "+arg)
			}
		}
	}
	return found
}
