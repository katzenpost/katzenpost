package common

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func TestNormalizeLegacyLongFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "separate value",
			args: []string{"-log_dir", "/tmp/log"},
			want: []string{"--log_dir", "/tmp/log"},
		},
		{
			name: "inline value",
			args: []string{"-log_level=INFO"},
			want: []string{"--log_level=INFO"},
		},
		{
			name: "value matching legacy flag",
			args: []string{"-log_dir", "-log_level"},
			want: []string{"--log_dir", "-log_level"},
		},
		{
			name: "terminator",
			args: []string{"--", "-log_dir", "/tmp/log"},
			want: []string{"--", "-log_dir", "/tmp/log"},
		},
		{
			name: "boolean followed by value flag",
			args: []string{"-validate-only", "-log_dir", "/tmp/log"},
			want: []string{"--validate-only", "--log_dir", "/tmp/log"},
		},
		{
			name: "short flag value matching legacy flag",
			args: []string{"-c", "-validate-only"},
			want: []string{"-c", "-validate-only"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test"}
			cmd.Flags().String("log_dir", "", "")
			cmd.Flags().String("log_level", "", "")
			cmd.Flags().Bool("validate-only", false, "")
			cmd.Flags().StringP("config", "c", "", "")

			original := append([]string(nil), test.args...)
			got := NormalizeLegacyLongFlags(cmd, test.args, "log_dir", "log_level", "validate-only")
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("NormalizeLegacyLongFlags() = %q, want %q", got, test.want)
			}
			if !reflect.DeepEqual(test.args, original) {
				t.Fatalf("NormalizeLegacyLongFlags() modified input: got %q, want %q", test.args, original)
			}
		})
	}
}
