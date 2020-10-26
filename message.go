package main

import (
	"time"

	"github.com/therecipe/qt/core"
)

const (
	StatusUnknown = iota
	StatusSent
	StatusNotSent
	StatusDelivered
)

// Message holds the data for a message
type Message struct {
	core.QObject

	MessageID string
	Nickname  string
	Avatar    string
	Message   string
	Outbound  bool
	Status    int
	Timestamp time.Time
}

type Messages []*Message

// Len is part of sort.Interface.
func (d Messages) Len() int {
	return len(d)
}

// Swap is part of sort.Interface.
func (d Messages) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

// Less is part of sort.Interface.
func (d Messages) Less(i, j int) bool {
	return d[i].Timestamp.Before(d[j].Timestamp)
}
