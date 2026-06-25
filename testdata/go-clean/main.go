package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"io"
	"net/http"
	"sync"
)

// P-17 Go PASS: crypto/rand (not the insecure PRNG)
func generateToken() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

// P-493 PASS: constant-time comparison — no token == string comparison
func verifyToken(token, expected []byte) bool {
	return subtle.ConstantTimeCompare(token, expected) == 1
}

// P-52 PASS: hmac.Equal also satisfies the timing-safe check
func verifyHMAC(sig, expected []byte) bool {
	return subtle.ConstantTimeCompare(sig, expected) == 1
}

// P-494 PASS: context-aware HTTP client — no bare http.Get
func fetchData(ctx context.Context, targetURL string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return err
}

// P-492 PASS: goroutines protected by mutex
var (
	mu             sync.Mutex
	sharedCounter  int
)

func incrementConcurrently() {
	go func() {
		mu.Lock()
		defer mu.Unlock()
		sharedCounter++
	}()
}

func main() {}
