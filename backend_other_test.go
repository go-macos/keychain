//go:build !darwin

package keychain

import (
	"errors"
	"testing"
)

// On non-darwin platforms every entry point must report ErrUnsupported while
// still building and cross-compiling.
func TestUnsupported(t *testing.T) {
	if !errors.Is(backendLoadErr, ErrUnsupported) {
		t.Fatalf("backendLoadErr = %v, want ErrUnsupported", backendLoadErr)
	}
	if err := Set("s", "a", []byte("x")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Set = %v, want ErrUnsupported", err)
	}
	if _, err := Get("s", "a"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Get = %v, want ErrUnsupported", err)
	}
	if err := Delete("s", "a"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Delete = %v, want ErrUnsupported", err)
	}
}
