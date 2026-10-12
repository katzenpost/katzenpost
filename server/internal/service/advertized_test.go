// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMergeAdvertized(t *testing.T) {
	plugin := map[string]map[string]interface{}{
		"courier": {"k": "v", "clash": "plugin"},
		"only":    {"p": 1},
	}
	static := map[string]map[string]interface{}{
		"courier": {"clash": "config", "s": "static"},
		"cfg":     {"x": "y"},
	}
	got := mergeAdvertized(plugin, static, func(string, string) {})
	require.Equal(t, map[string]map[string]interface{}{
		"courier": {"k": "v", "clash": "config", "s": "static"},
		"only":    {"p": 1},
		"cfg":     {"x": "y"},
	}, got)
	require.Equal(t, "plugin", plugin["courier"]["clash"], "inputs are not modified")

	var clashes []string
	mergeAdvertized(plugin, static, func(capa, key string) { clashes = append(clashes, capa+"/"+key) })
	require.Equal(t, []string{"courier/clash"}, clashes)

	require.Empty(t, mergeAdvertized(nil, nil, func(string, string) {}))
}
