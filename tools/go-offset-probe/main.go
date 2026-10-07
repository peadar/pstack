package main

import "runtime"

// Keep this executable small while linking and retaining DWARF for runtime's
// internal types. pstack-mkgooff reads runtime.g and runtime.gobuf from it.
func main() {
	runtime.GC()
}
