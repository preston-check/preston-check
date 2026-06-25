package main

import (
	"math/rand"
	"net/http"
)

// P-17 Go: uses math/rand (not crypto/rand)
func generateToken() int {
	return rand.Intn(1000000)
}

// P-493: == comparison on a "token" variable — timing oracle risk
func verifyToken(token, expected string) bool {
	return token == expected
}

// P-494: bare http.Get without context.Context
func fetchWebhook(url string) (*http.Response, error) {
	return http.Get(url)
}

// P-492: goroutine spawned without any sync primitive
var sharedCounter int

func incrementConcurrently() {
	go func() { sharedCounter++ }()
	go func() { sharedCounter++ }()
}

func main() {}
