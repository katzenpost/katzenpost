// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	clientcommon "github.com/katzenpost/katzenpost/client/common"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/cmd/internal/mixclient"
	"github.com/katzenpost/katzenpost/common"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

const motdCapability = "motd"

var (
	errNoDocument = errors.New("no PKI document yet")
	errNoMOTD     = errors.New("no service node advertises motd")
)

func motdService(doc *cpki.Document) (*clientcommon.ServiceDescriptor, error) {
	if doc == nil {
		return nil, errNoDocument
	}
	services := clientcommon.FindServices(motdCapability, doc)
	if len(services) == 0 {
		return nil, errNoMOTD
	}
	return services[rand.NewMath().Intn(len(services))], nil
}

func motdText(reply []byte) string {
	return string(bytes.TrimRight(reply, "\x00"))
}

func fetchMOTD(thinClient *thin.ThinClient, timeout time.Duration) (string, error) {
	doc := thinClient.PKIDocument()
	desc, err := motdService(doc)
	if err != nil {
		return "", err
	}
	if timeout <= 0 {
		timeout = mixclient.RoundTripTimeout(doc)
	}
	id := hash.Sum256(desc.MixDescriptor.IdentityKey)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := thinClient.BlockingSendMessageWithResult(ctx, []byte(motdCapability), &id, desc.RecipientQueueID, mixclient.ReplySlop(doc))
	if err != nil {
		return "", fmt.Errorf("no motd reply from %s within %v: %w", desc.MixDescriptor.Name, timeout, err)
	}
	return motdText(res.Payload), nil
}

func newRootCommand() *cobra.Command {
	var (
		configFile string
		thinOnly   bool
		logLevel   string
		timeout    time.Duration
	)
	cmd := &cobra.Command{
		Use:          "motd",
		Short:        "Fetch and print the mixnet's message of the day",
		SilenceUsage: true,
		Example: `  motd -c thinclient.toml --thin
  motd -c client.toml --timeout 2m`,
		RunE: func(cmd *cobra.Command, args []string) error {
			thinClient, daemon := mixclient.Connect(configFile, thinOnly, mixclient.LogFilePath("motd"), logLevel)
			defer mixclient.Close(thinClient, daemon)
			mixclient.CloseOnInterrupt(thinClient, daemon)
			text, err := fetchMOTD(thinClient, timeout)
			if err != nil {
				return err
			}
			if !strings.HasSuffix(text, "\n") {
				text += "\n"
			}
			_, err = os.Stdout.WriteString(text)
			return err
		},
	}
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "configuration file")
	cmd.Flags().BoolVar(&thinOnly, "thin", false, "use thin client mode (connect to existing daemon)")
	cmd.Flags().StringVar(&logLevel, "log-level", "ERROR", "logging level (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "how long to wait for the reply (0: derived from the consensus)")
	cmd.MarkFlagRequired("config")
	return cmd
}

func main() {
	common.ExecuteWithFang(newRootCommand())
}
