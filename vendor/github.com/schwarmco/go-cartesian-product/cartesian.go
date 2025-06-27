package cartesian

// Iter takes interface-slices and returns a channel, receiving cartesian products
func Iter(params ...[]interface{}) chan []interface{} {
	// create channel
	c := make(chan []interface{})
	if len(params) == 0 {
		close(c)
		return c // Return a safe value for nil/empty params.
	}
	go func() {
		iterate(c, params[0], []interface{}{}, params[1:]...)
		close(c)
	}()
	return c
}

func iterate(channel chan []interface{}, topLevel, result []interface{}, needUnpacking ...[]interface{}) {
	if len(needUnpacking) == 0 {
		for _, p := range topLevel {
			channel <- append(append([]interface{}{}, result...), p)
		}
		return
	}
	for _, p := range topLevel {
		iterate(channel, needUnpacking[0], append(result, p), needUnpacking[1:]...)
	}
}
