// Copyright (c) the go-macos/keychain authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Command touchid-demo is a hands-on check of the LocalAuthentication (Touch ID)
// surface added to the keychain package. It cannot be automated — a human must
// touch the sensor — so it lives here rather than in a test.
//
// Run it on a Mac with Touch ID:
//
//	go run ./cmd/touchid-demo
//
// It first reports whether a biometric can be evaluated (no prompt), then calls
// Authenticate, which raises the real system Touch ID prompt. Authenticate uses
// LAContext.evaluatePolicy directly, so it needs no keychain entitlement and
// works from an unsigned `go run` binary — unlike storing an access-controlled
// item, which requires a signed app.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-macos/keychain"
)

func main() {
	bt, err := keychain.CanEvaluate()
	if err != nil {
		if errors.Is(err, keychain.ErrUnsupported) {
			fmt.Println("Touch ID is a macOS-only feature; this build cannot use it.")
			os.Exit(1)
		}
		fmt.Printf("No usable biometric on this Mac: %v (reported hardware: %v)\n", err, bt)
		os.Exit(1)
	}
	fmt.Printf("Biometric available: %v\n", bt)
	fmt.Println("Requesting authentication — the system Touch ID prompt should appear now…")

	if err := keychain.Authenticate("Unlock the keychain demo"); err != nil {
		switch {
		case errors.Is(err, keychain.ErrUserCanceled):
			fmt.Println("Canceled by the user.")
		default:
			fmt.Printf("Authentication failed: %v\n", err)
		}
		os.Exit(1)
	}
	fmt.Println("✓ Authenticated with Touch ID.")
}
