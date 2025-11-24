package main

import (
	"math/rand"
	"testing"
	"time"
)

func init() {
	// Seed the math/rand generator with current time for randomness
	rand.Seed(time.Now().UnixNano())

	// Register the malicious /evil entity before running tests
	if err := RegisterEvil(); err != nil {
		panic(err) // stop execution if registration fails
	}
}

func BenchmarkEvilCheck(b *testing.B) {
	// Report memory allocations during benchmark
	b.ReportAllocs()

	// Reset timer to ignore setup time
	b.ResetTimer()

	// Run the benchmark loop b.N times
	for i := 0; i < b.N; i++ {
		// Pick a random user for this iteration
		user := PickRandomUser()

		// Check the fake vote
		_, err := EvilCheck(user)
		if err != nil {
			b.Fatalf("EvilCheck error: %v", err) // fail benchmark if error occurs
		}
	}
}
