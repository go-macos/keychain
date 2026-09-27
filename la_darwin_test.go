//go:build darwin

package keychain

import (
	"errors"
	"testing"
	"time"

	"github.com/go-macos/objc"
)

// These tests exercise the real LocalAuthentication FFI on-device, but only the
// paths that do NOT raise a biometric prompt: canEvaluatePolicy:, LAContext
// lifecycle and NSError classification. The one prompting path
// (realAuthenticate → evaluatePolicy:localizedReason:reply:) cannot be driven
// unattended — a human must touch the sensor — so it is proven by the
// cmd/touchid-demo tool, not here.

// TestLoadLAResolved asserts the LocalAuthentication surface loaded on a normal
// macOS host (the success path of loadLA). A build where the framework is
// genuinely absent is not something this suite can create, so a load failure is
// reported rather than silently passing.
func TestLoadLAResolved(t *testing.T) {
	if laLoadErr != nil {
		t.Fatalf("LocalAuthentication unavailable on this host: %v", laLoadErr)
	}
}

// TestRealCanEvaluate drives the real canEvaluatePolicy: probe. It runs on any
// Mac: one with an enrolled sensor reports (a non-None biometry, nil), one
// without reports (some biometry classification, a biometry sentinel error) —
// e.g. a headless CI runner returns ErrBiometryNotAvailable. The assertion is
// the invariant both must satisfy, so it exercises the ok and the
// error-classifying branches across environments without assuming hardware.
func TestRealCanEvaluate(t *testing.T) {
	bt, err := realCanEvaluate()
	if err != nil {
		if !errors.Is(err, ErrBiometryNotAvailable) &&
			!errors.Is(err, ErrBiometryNotEnrolled) &&
			!errors.Is(err, ErrBiometryLockout) &&
			!errors.Is(err, ErrPasscodeNotSet) &&
			!errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("canEvaluate error not a known biometry sentinel: %v", err)
		}
		t.Logf("no usable biometry on this host: %v (biometry=%v)", err, bt)
		return
	}
	if bt == BiometryNone {
		t.Fatalf("canEvaluate succeeded but biometry type is None")
	}
	t.Logf("biometry available: %v", bt)
}

// TestRealAuthContextLifecycle covers realNewAuthContext (with and without a
// reuse window) and realCloseAuthContext (a live handle and the 0 no-op).
func TestRealAuthContextLifecycle(t *testing.T) {
	if laLoadErr != nil {
		t.Skipf("LocalAuthentication unavailable: %v", laLoadErr)
	}
	for _, reuse := range []time.Duration{0, 30 * time.Second} {
		h, err := realNewAuthContext(reuse)
		if err != nil {
			t.Fatalf("realNewAuthContext(%v): %v", reuse, err)
		}
		if h == 0 {
			t.Fatalf("realNewAuthContext(%v): got handle 0", reuse)
		}
		realCloseAuthContext(h)
	}
	realCloseAuthContext(0) // no-op, must not crash
}

// TestLAErrorFromNSError covers both branches of laErrorFromNSError: a nil
// NSError (an unexpected "failed with no error") maps to the generic
// authentication failure, and a real NSError carrying an LA code is classified
// by mapLAError.
func TestLAErrorFromNSError(t *testing.T) {
	if got := laErrorFromNSError(0); !errors.Is(got, ErrAuthenticationFailed) {
		t.Fatalf("laErrorFromNSError(nil) = %v, want ErrAuthenticationFailed", got)
	}
	// Build a genuine NSError with the user-cancel code and confirm it is
	// classified, so the non-nil branch is covered deterministically (not only
	// when the host happens to lack biometrics).
	nsErr := objc.ID(objc.GetClass("NSError")).Send(
		objc.Sel("errorWithDomain:code:userInfo:"),
		objc.NSString("com.apple.LocalAuthentication"), laErrUserCancel, objc.ID(0))
	if nsErr == 0 {
		t.Fatal("could not construct an NSError")
	}
	if got := laErrorFromNSError(nsErr); !errors.Is(got, ErrUserCanceled) {
		t.Fatalf("laErrorFromNSError(userCancel) = %v, want ErrUserCanceled", got)
	}
}
