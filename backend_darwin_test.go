//go:build darwin

package keychain

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

// The (service, account) pairs used by the on-device tests. They are unique to
// this package so a run never disturbs a real credential, and each test cleans
// up after itself.
const (
	testService = "com.go-macos.keychain.test"
	// errSecMissingEntitlement is returned by SecItemAdd for an
	// access-controlled item when the calling binary is not code-signed with a
	// keychain-access-group entitlement — the case for a bare `go test`
	// binary. A signed .app (weft, the reddit reader) has it.
	errSecMissingEntitlement int32 = -34018
)

func uniqueAccount(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
}

// TestPlumbing confirms every CoreFoundation + Security symbol resolved and
// that CFData / CFAccessControl / CFDictionary construction works against the
// real frameworks, without touching a stored item.
func TestPlumbing(t *testing.T) {
	if backendLoadErr != nil {
		t.Fatalf("backend load failed: %v", backendLoadErr)
	}
	b := []byte("hello keychain 123")
	d := cfDataCreate(0, &b[0], len(b))
	if d == 0 {
		t.Fatal("CFDataCreate returned nil")
	}
	defer cfRelease(d)
	if n := cfDataGetLength(d); n != len(b) {
		t.Fatalf("CFDataGetLength = %d, want %d", n, len(b))
	}

	var acErr uintptr
	ac := secACCreate(0, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, 0, &acErr)
	if ac == 0 {
		t.Fatal("SecAccessControlCreateWithFlags(0) returned nil")
	}
	cfRelease(ac)

	for name, v := range map[string]uintptr{
		"kSecClass":                kSecClass,
		"kSecClassGenericPassword": kSecClassGenericPassword,
		"kSecAttrService":          kSecAttrService,
		"kSecAttrAccount":          kSecAttrAccount,
		"kSecValueData":            kSecValueData,
		"kSecReturnData":           kSecReturnData,
		"kSecMatchLimit":           kSecMatchLimit,
		"kSecMatchLimitOne":        kSecMatchLimitOne,
		"kSecAttrAccessControl":    kSecAttrAccessControl,
		"kSecAttrAccessible":       kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		"kCFBooleanTrue":           kCFBooleanTrue,
		"keyCallBacks":             kCFTypeDictionaryKeyCallBacks,
		"valueCallBacks":           kCFTypeDictionaryValueCallBacks,
	} {
		if v == 0 {
			t.Errorf("constant %s is nil", name)
		}
	}
}

// TestRoundTrip is the real store -> get -> update -> delete cycle against the
// live login Keychain on this machine (plain generic password, no biometric
// prompt).
func TestRoundTrip(t *testing.T) {
	if backendLoadErr != nil {
		t.Fatalf("backend load failed: %v", backendLoadErr)
	}
	acct := uniqueAccount(t)
	t.Cleanup(func() { _ = Delete(testService, acct) })

	// Absent to begin with.
	if _, err := Get(testService, acct); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pre-set Get = %v, want ErrNotFound", err)
	}

	// Store (add path).
	secret := []byte("s3cr3t-" + acct)
	if err := Set(testService, acct, secret); err != nil {
		t.Fatalf("Set (add): %v", err)
	}
	got, err := Get(testService, acct)
	if err != nil {
		t.Fatalf("Get after add: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("Get = %q, want %q", got, secret)
	}

	// Overwrite (update path).
	rotated := []byte("rotated-" + acct)
	if err := Set(testService, acct, rotated); err != nil {
		t.Fatalf("Set (update): %v", err)
	}
	got, err = Get(testService, acct)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if !bytes.Equal(got, rotated) {
		t.Fatalf("Get after update = %q, want %q", got, rotated)
	}

	// Delete, then confirm the miss and that a second delete is a no-op.
	if err := Delete(testService, acct); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get(testService, acct); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-delete Get = %v, want ErrNotFound", err)
	}
	if err := Delete(testService, acct); err != nil {
		t.Fatalf("Delete of absent item = %v, want nil", err)
	}
}

// TestAccessControlRoundTrip exercises the SecAccessControl path with no
// interactive flag (0), so the item is protected at rest yet readable without a
// biometric prompt — keeping the test autonomous. The UserPresence flag is a
// pure pass-through to SecAccessControlCreateWithFlags; reading such an item
// prompts for Touch ID and so cannot be verified unattended.
func TestAccessControlRoundTrip(t *testing.T) {
	if backendLoadErr != nil {
		t.Fatalf("backend load failed: %v", backendLoadErr)
	}
	acct := uniqueAccount(t)
	t.Cleanup(func() { _ = Delete(testService, acct) })

	secret := []byte("ac-secret-" + acct)
	err := Set(testService, acct, secret, WithAccessControl(0))
	var e *Error
	if errors.As(err, &e) && e.Status == errSecMissingEntitlement {
		// The access-control code path (delete-then-add through a fresh
		// SecAccessControl) ran; only the final SecItemAdd was rejected because
		// this unsigned test binary lacks the entitlement. Verified for real
		// from the signed weft / reddit .app bundles.
		t.Skipf("access-controlled add needs a signed binary (OSStatus %d); code path exercised", e.Status)
	}
	if err != nil {
		t.Fatalf("Set(WithAccessControl(0)): %v", err)
	}
	got, err := Get(testService, acct)
	if err != nil {
		t.Fatalf("Get access-controlled item: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("Get = %q, want %q", got, secret)
	}

	// Re-store to exercise the access-controlled delete-then-add replace path.
	if err := Set(testService, acct, []byte("ac-rotated"), WithAccessControl(0)); err != nil {
		t.Fatalf("Set(WithAccessControl) replace: %v", err)
	}
	got, err = Get(testService, acct)
	if err != nil {
		t.Fatalf("Get after AC replace: %v", err)
	}
	if !bytes.Equal(got, []byte("ac-rotated")) {
		t.Fatalf("Get after AC replace = %q, want ac-rotated", got)
	}
}

// TestSetEmptyOnDevice confirms the empty-secret guard fires before any FFI.
func TestSetEmptyOnDevice(t *testing.T) {
	if err := Set(testService, "unused", nil); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("Set(nil) = %v, want ErrEmptySecret", err)
	}
}
