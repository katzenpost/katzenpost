// server.go - Reunion server.
// Copyright (C) 2019  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package server provides the Reunion protocol server.
package server

import (
	"container/list"
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/katzenpost/reunion/commands"
	"github.com/ugorji/go/codec"
)

var cborHandle = new(codec.CborHandle)

// ReunionDatabase is an interface which represents the
// Reunion DB that protocol clients interact with.
type ReunionDatabase interface {
	// Query sends a query command to the Reunion DB and returns the
	// response command or an error.
	Query(command commands.Command, haltCh chan interface{}) (commands.Command, error)
}

// LockedList is used to coordinate access to it's linked list
// of T2 and T3 messages.
type LockedList struct {
	sync.RWMutex

	list *list.List
}

// NewLockedList creates a new LockedList.
func NewLockedList() *LockedList {
	return &LockedList{
		list: list.New(),
	}
}

// Append to linked list after taking mutex.
func (l *LockedList) Append(item interface{}) {
	l.Lock()
	defer l.Unlock()

	l.list.PushBack(item)
}

// Range calls f sequentially for each item in the list.
// If f returns false, Range stops the iteration.
func (l *LockedList) Range(f func(item interface{}) bool) {
	l.RLock()
	defer l.RUnlock()

	for e := l.list.Front(); e != nil; e = e.Next() {
		if !f(e.Value) {
			break
		}
	}
}

// T1Message
type T1Message struct {
	// Payload contains the T1 message.
	Payload []byte
}

// T2Message
type T2Message struct {
	// Payload contains the T2 message.
	Payload []byte
}

// T3Message
type T3Message struct {
	// T2Hash is the hash of the T2 message which this T3 message is replying.
	T2Hash [sha256.Size]byte

	// Payload contains the T3 message.
	Payload []byte
}

// T2T3Message
type T2T3Message struct {
	// T2Hash is the hash of the T2 message which this T3 message is replying.
	T2Hash *[sha256.Size]byte

	// T2Payload contains the T2 message.
	T2Payload []byte

	// T3Payload contains the T3 message.
	T3Payload []byte
}

// SerializableReunionState represents the ReunionState in
// a serializable struct type.
type SerializableReunionState struct {
	// T1Map is a slice of the SendT1 command received from a client.
	// t1 hash -> t1
	T1Map map[[32]byte][]byte

	// MessageMap: t1 hash -> slice of
	MessageMap map[[32]byte][]*T2T3Message
}

// ReunionState is the state of the Reunion DB.
// This is the type which is fetched by the FetchState
// command.
type ReunionState struct {
	// t1Map is a slice of the SendT1 command received from a client.
	t1Map *sync.Map

	// messageMap maps the t1 hash to a linked list containing
	// t2 and t3 messages, the LockedList defined above.
	messageMap *sync.Map
}

// NewReunionStateChunk creates a new ReunionStateChunk.
func NewReunionState() *ReunionState {
	return &ReunionState{
		t1Map:      new(sync.Map),
		messageMap: new(sync.Map),
	}
}

// Serializable returns a *SerializableReunionState copy of the
// data encapsulated in *ReunionState.
func (s *ReunionState) Serializable() (*SerializableReunionState, error) {
	c := SerializableReunionState{
		T1Map:      make(map[[32]byte][]byte),
		MessageMap: make(map[[32]byte][]*T2T3Message),
	}
	var err error
	s.t1Map.Range(func(t1hash, t1 interface{}) bool {
		t1hashAr, ok := t1hash.([32]byte)
		if !ok {
			err = errors.New("Range failure, invalid input type")
			return false
		}
		t1bytes, ok := t1.([]byte)
		if !ok {
			err = errors.New("Range failure, invalid input type")
			return false
		}
		c.T1Map[t1hashAr] = t1bytes
		return true
	})
	if err != nil {
		return nil, err
	}
	s.messageMap.Range(func(t1hash, messages interface{}) bool {
		t1hashAr, ok := t1hash.([32]byte)
		if !ok {
			err = errors.New("Range failure, invalid key type")
			return false
		}
		_, ok = c.MessageMap[t1hashAr]
		if !ok {
			c.MessageMap[t1hashAr] = make([]*T2T3Message, 0)
		}
		messageList, ok := messages.(*LockedList)
		if !ok {
			err = errors.New("Range failure, invalid list type")
			return false
		}
		messageList.Range(func(item interface{}) bool {
			switch message := item.(type) {
			case *T2Message:
				c.MessageMap[t1hashAr] = append(c.MessageMap[t1hashAr], &T2T3Message{
					T2Hash:    nil,
					T2Payload: message.Payload,
					T3Payload: nil,
				})
				return true
			case *T3Message:
				c.MessageMap[t1hashAr] = append(c.MessageMap[t1hashAr], &T2T3Message{
					T2Hash:    &message.T2Hash,
					T2Payload: nil,
					T3Payload: message.Payload,
				})
				return true
			default:
				err = errors.New("Marshal failure due to invalid message type")
				return false
			}
		})
		return true
	})
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// Marshal returns a CBOR serialization of an inconsistent snapshot.
func (s *ReunionState) Marshal() ([]byte, error) {
	c, err := s.Serializable()
	if err != nil {
		return nil, err
	}
	var serialized []byte
	err = codec.NewEncoderBytes(&serialized, cborHandle).Encode(&c)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

// Unmarshal deserializes the state CBOR blob.
func (s *ReunionState) Unmarshal(data []byte) error {
	state := SerializableReunionState{
		T1Map:      make(map[[32]byte][]byte),
		MessageMap: make(map[[32]byte][]*T2T3Message),
	}
	err := codec.NewDecoderBytes(data, cborHandle).Decode(&state)
	if err != nil {
		return err
	}
	for _, t1 := range state.T1Map {
		err := s.AppendMessage(&commands.SendT1{
			Payload: t1,
		})
		if err != nil {
			return err
		}
	}
	for t1hash, messages := range state.MessageMap {
		for _, t2t3 := range messages {
			if len(t2t3.T2Payload) > 0 {
				sendT2 := commands.SendT2{
					T1Hash:  t1hash,
					Payload: t2t3.T2Payload,
				}
				err := s.AppendMessage(&sendT2)
				if err != nil {
					return err
				}
			} else if len(t2t3.T3Payload) > 0 {
				sendT3 := commands.SendT3{
					T1Hash:  t1hash,
					T2Hash:  *t2t3.T2Hash,
					Payload: t2t3.T3Payload,
				}
				err := s.AppendMessage(&sendT3)
				if err != nil {
					return err
				}
			} else {
				return errors.New("Unmarshal failure due to a zero size message")
			}
		}
	}
	return nil
}

// AppendMessage receives a message which can be one of these types:
// *commands.SendT1
// *commands.SendT2
// *commands.SendT3
func (s *ReunionState) AppendMessage(message interface{}) error {
	switch mesg := message.(type) {
	case *commands.SendT1:
		h := sha256.New()
		h.Write(mesg.Payload)
		t1Hash := h.Sum(nil)
		t1HashAr := [sha256.Size]byte{}
		copy(t1HashAr[:], t1Hash)
		_, ok := s.t1Map.Load(t1HashAr)
		if ok {
			errors.New("cannot append T1, already present")
		}
		s.t1Map.Store(t1HashAr, mesg.Payload)
		s.messageMap.Store(t1HashAr, NewLockedList())
		return nil
	case *commands.SendT2:
		l, ok := s.messageMap.Load(mesg.T1Hash)
		if ok {
			messageList, ok := l.(*LockedList)
			if !ok {
				return errors.New("wtf, invalid list type")
			}
			messageList.Append(&T2Message{
				Payload: mesg.Payload,
			})
		} else {
			messageList := NewLockedList()
			messageList.Append(&T2Message{
				Payload: mesg.Payload,
			})
			s.messageMap.Store(mesg.T1Hash, messageList)
		}
		return nil
	case *commands.SendT3:
		l, ok := s.messageMap.Load(mesg.T1Hash)
		if ok {
			messageList, ok := l.(*LockedList)
			if !ok {
				return errors.New("wtf, invalid list type")
			}
			messageList.Append(&T3Message{
				T2Hash:  mesg.T2Hash,
				Payload: mesg.Payload,
			})
		} else {
			messageList := NewLockedList()
			messageList.Append(&T3Message{
				T2Hash:  mesg.T2Hash,
				Payload: mesg.Payload,
			})
			s.messageMap.Store(mesg.T1Hash, messageList)
		}
		return nil
	default:
		return errors.New("ReunionState.AppendMessage failued: unknown message type")
	}
	// unreached
}
