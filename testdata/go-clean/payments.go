package main

import (
	"context"
	"database/sql"

	"github.com/shopspring/decimal"
)

// P-491 PASS: decimal.Decimal for monetary fields — no float64/float32
func processPayment(amount decimal.Decimal, price decimal.Decimal) decimal.Decimal {
	fee := amount.Mul(decimal.NewFromFloat(0.01))
	return price.Add(fee)
}

type Account struct {
	balance decimal.Decimal
	cost    decimal.Decimal
}

// P-494/P-495 PASS: context-aware query with parameter placeholder — no fmt.Sprintf
func getUser(ctx context.Context, db *sql.DB, userID string) *sql.Row {
	return db.QueryRowContext(ctx, "SELECT * FROM users WHERE id = $1", userID)
}

// P-490 PASS: error is always checked — no _, _ = pattern
func riskyOperation() (int, error) { return 42, nil }

func caller() {
	val, err := riskyOperation()
	if err != nil {
		return
	}
	_ = val
}
