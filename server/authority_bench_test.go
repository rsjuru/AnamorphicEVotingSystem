package main

import (
	"testing"
)

// Measures the performance of the authority setup process.
func BenchmarkAuthoritySetup(b *testing.B) {
	// Loop b.N times, which is controlled by the Go benchmark runner
	for i := 0; i < b.N; i++ {
		// Initializes the voting authority's parameters
		setUpAuthority()
	}
}
