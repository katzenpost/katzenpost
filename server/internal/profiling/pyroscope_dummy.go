//go:build !pyroscope
// +build !pyroscope

package profiling

// Start is a dummy function that does nothing.
func Start() error {
	return nil
}
