package client2

import (
	"crypto/rand"
	"fmt"
	"os"
	"sync"

	"github.com/charmbracelet/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
)

type EgressFanOut struct {
	worker.Worker

	log          *log.Logger
	client       *Client
	destinations sync.Map // mapping [32]byte -> chan *Request
	inCh         chan *Request
}

func newFanOut(doc *cpki.Document, client *Client) (*EgressFanOut, error) {
	var destinations sync.Map
	for i := 0; i < len(doc.Providers); i++ {
		_, ok := doc.Providers[i].Kaetzchen["echo"]
		if ok {
			destinations.Store(doc.Providers[i].IdentityKey.Sum256(), make(chan *Request))
		} else {
			return nil, fmt.Errorf("Provider %s is not configured with echo service", doc.Providers[i].Name)
		}
	}
	return &EgressFanOut{
		log: log.NewWithOptions(os.Stderr, log.Options{
			ReportTimestamp: true,
			Prefix:          "client2/destination_fanout",
		}),
		destinations: destinations,
		inCh:         make(chan *Request),
	}, nil
}

func (f *EgressFanOut) Start() {
	f.destinations.Range(
		func(_, outCh any) bool {
			ch := outCh.(chan *Request)
			f.Go(func() {
				f.egressWorker(ch)
			})
			return true
		},
	)

	f.Go(f.ingressWorker)
}

func (f *EgressFanOut) Ingress(message *Request) {
	f.inCh <- message
}

func (f *EgressFanOut) egressWorker(outCh chan *Request) {
	for {
		select {
		case <-f.HaltCh():
			return
		case message := <-outCh:
			desc, err := f.client.CurrentDocument().GetProviderByKeyHash(message.DestinationIdHash)
			if err != nil {
				panic(err)
			}
			surbID := [sConstants.SURBIDLength]byte{}
			_, err = rand.Read(surbID[:])
			if err != nil {
				panic(err)
			}
			//packet, surbKeys, rtt, err := f.client.ComposeSphinxPacket(message.RecipientQueueID, desc.Name, &surbID, message.Payload)
			packet, _, _, err := f.client.ComposeSphinxPacket(message.RecipientQueueID, desc.Name, &surbID, message.Payload)
			if err != nil {
				panic(err)
			}
			err = f.client.SendSphinxPacket(packet)
			if err != nil {
				panic(err)
			}

		}
	}
}

func (f *EgressFanOut) ingressWorker() {
	for {
		select {
		case <-f.HaltCh():
			return
		case message := <-f.inCh:
			queueCh, ok := f.destinations.Load(message.DestinationIdHash)
			if !ok {
				log.Infof("destination id hash not found: %x", message.DestinationIdHash[:])
				continue
			}
			ch := queueCh.(chan *Request)
			select {
			case <-f.HaltCh():
				return
			case ch <- message:
			}

		}
	}
}
