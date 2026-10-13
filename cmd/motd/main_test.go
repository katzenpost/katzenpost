// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestMOTDTextDropsThePadding(t *testing.T) {
	reply := append([]byte("hello from the testnet"), make([]byte, 64)...)
	require.Equal(t, "hello from the testnet", motdText(reply))
}

func TestMOTDServiceLookup(t *testing.T) {
	_, err := motdService(nil)
	require.ErrorIs(t, err, errNoDocument)
	doc := &cpki.Document{ServiceNodes: []*cpki.MixDescriptor{
		{Name: "servicenode1", Kaetzchen: map[string]map[string]interface{}{"echo": {"endpoint": "+echo"}}},
	}}
	_, err = motdService(doc)
	require.ErrorIs(t, err, errNoMOTD)
	doc.ServiceNodes = append(doc.ServiceNodes, &cpki.MixDescriptor{Name: "servicenode2", Kaetzchen: map[string]map[string]interface{}{"motd": {"endpoint": "+motd"}}})
	desc, err := motdService(doc)
	require.NoError(t, err)
	require.Equal(t, "servicenode2", desc.MixDescriptor.Name)
	require.Equal(t, []byte("+motd"), desc.RecipientQueueID)
}
