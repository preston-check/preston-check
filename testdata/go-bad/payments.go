package main

import (
	"database/sql"
	"fmt"
)

// P-491 Go: float64/float32 for financial fields — precision loss risk
func processPayment(amount float64, price float64) float64 {
	fee := amount * 0.01
	return price + fee
}

// P-491 Go: balance and cost also trigger the pattern
type Account struct {
	balance float64
	cost    float32
}

// P-495 Go: SQL injection via fmt.Sprintf in QueryContext
// Note: first arg intentionally omitted to place fmt.Sprintf without a
// comma between the opening paren and the Sprintf call — this is the shape
// the check's grep pattern matches (no comma before fmt.Sprintf).
func getUser(db *sql.DB, userID string) {
	db.QueryContext(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))
}

// P-490 Go: both return values discarded — errors silently swallowed
func riskyOperation() (int, error) { return 42, nil }

func caller() {
	_, _ = riskyOperation()
}
