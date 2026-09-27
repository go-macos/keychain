package keychain

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// withFakeBackend swaps the package seams for test doubles and restores them
// afterwards, so the OS-independent logic in keychain.go is exercised on every
// platform without a live Keychain.
func withFakeBackend(t *testing.T, loadErr error, set func(string, string, []byte, config) int32, get func(string, string, uintptr) ([]byte, int32), del func(string, string) int32) {
	t.Helper()
	origErr, origSet, origGet, origDel := backendLoadErr, backendSet, backendGet, backendDelete
	t.Cleanup(func() {
		backendLoadErr, backendSet, backendGet, backendDelete = origErr, origSet, origGet, origDel
	})
	backendLoadErr, backendSet, backendGet, backendDelete = loadErr, set, get, del
}

// withFakeLA swaps the LocalAuthentication seams for test doubles and restores
// them afterwards, so the biometric entry points reach full coverage without a
// live LAContext.
func withFakeLA(t *testing.T, loadErr error, newCtx func(time.Duration) (uintptr, error), closeCtx func(uintptr), canEval func() (BiometryType, error), auth func(uintptr, string) error) {
	t.Helper()
	oErr, oNew, oClose, oCan, oAuth := backendLoadErr, backendNewAuthContext, backendCloseAuthContext, backendCanEvaluate, backendAuthenticate
	t.Cleanup(func() {
		backendLoadErr, backendNewAuthContext, backendCloseAuthContext, backendCanEvaluate, backendAuthenticate = oErr, oNew, oClose, oCan, oAuth
	})
	backendLoadErr, backendNewAuthContext, backendCloseAuthContext, backendCanEvaluate, backendAuthenticate = loadErr, newCtx, closeCtx, canEval, auth
}

func TestSetEmptySecret(t *testing.T) {
	called := false
	withFakeBackend(t, nil,
		func(string, string, []byte, config) int32 { called = true; return errSecSuccess },
		nil, nil)
	if err := Set("svc", "acct", nil); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("Set(nil) error = %v, want ErrEmptySecret", err)
	}
	if err := Set("svc", "acct", []byte{}); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("Set([]) error = %v, want ErrEmptySecret", err)
	}
	if called {
		t.Fatal("backendSet must not be called for an empty secret")
	}
}

func TestSetSuccessAndOptions(t *testing.T) {
	var gotSvc, gotAcct string
	var gotSecret []byte
	var gotCfg config
	withFakeBackend(t, nil,
		func(s, a string, sec []byte, c config) int32 {
			gotSvc, gotAcct, gotSecret, gotCfg = s, a, sec, c
			return errSecSuccess
		}, nil, nil)

	if err := Set("svc", "acct", []byte("hunter2"), WithAccessControl(UserPresence|DevicePasscode)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if gotSvc != "svc" || gotAcct != "acct" || !bytes.Equal(gotSecret, []byte("hunter2")) {
		t.Fatalf("backendSet got (%q,%q,%q)", gotSvc, gotAcct, gotSecret)
	}
	if !gotCfg.useAC || gotCfg.acFlags != UserPresence|DevicePasscode {
		t.Fatalf("config = %+v, want useAC with UserPresence|DevicePasscode", gotCfg)
	}
}

func TestSetBackendError(t *testing.T) {
	withFakeBackend(t, nil,
		func(string, string, []byte, config) int32 { return -42 },
		nil, nil)
	var e *Error
	err := Set("svc", "acct", []byte("x"))
	if !errors.As(err, &e) {
		t.Fatalf("Set error = %v, want *Error", err)
	}
	if e.Op != "set" || e.Status != -42 {
		t.Fatalf("Error = %+v, want {set -42}", e)
	}
}

func TestGetSuccess(t *testing.T) {
	withFakeBackend(t, nil, nil,
		func(string, string, uintptr) ([]byte, int32) { return []byte("secret"), errSecSuccess },
		nil)
	b, err := Get("svc", "acct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(b, []byte("secret")) {
		t.Fatalf("Get = %q, want secret", b)
	}
}

func TestGetNotFound(t *testing.T) {
	withFakeBackend(t, nil, nil,
		func(string, string, uintptr) ([]byte, int32) { return nil, errSecItemNotFound },
		nil)
	if _, err := Get("svc", "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get error = %v, want ErrNotFound", err)
	}
}

func TestGetOtherError(t *testing.T) {
	withFakeBackend(t, nil, nil,
		func(string, string, uintptr) ([]byte, int32) { return nil, -25293 },
		nil)
	var e *Error
	_, err := Get("svc", "acct")
	if !errors.As(err, &e) || e.Op != "get" || e.Status != -25293 {
		t.Fatalf("Get error = %v, want *Error{get -25293}", err)
	}
}

func TestDeleteSuccess(t *testing.T) {
	withFakeBackend(t, nil, nil, nil,
		func(string, string) int32 { return errSecSuccess })
	if err := Delete("svc", "acct"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestDeleteMissingIsNil(t *testing.T) {
	withFakeBackend(t, nil, nil, nil,
		func(string, string) int32 { return errSecItemNotFound })
	if err := Delete("svc", "acct"); err != nil {
		t.Fatalf("Delete of absent item = %v, want nil", err)
	}
}

func TestDeleteOtherError(t *testing.T) {
	withFakeBackend(t, nil, nil, nil,
		func(string, string) int32 { return -99 })
	var e *Error
	err := Delete("svc", "acct")
	if !errors.As(err, &e) || e.Op != "delete" || e.Status != -99 {
		t.Fatalf("Delete error = %v, want *Error{delete -99}", err)
	}
}

func TestLoadErrPropagates(t *testing.T) {
	sentinel := errors.New("boom")
	withFakeBackend(t, sentinel,
		func(string, string, []byte, config) int32 { t.Fatal("backendSet called"); return 0 },
		func(string, string, uintptr) ([]byte, int32) { t.Fatal("backendGet called"); return nil, 0 },
		func(string, string) int32 { t.Fatal("backendDelete called"); return 0 })

	if err := Set("s", "a", []byte("x")); !errors.Is(err, sentinel) {
		t.Fatalf("Set error = %v, want sentinel", err)
	}
	if _, err := Get("s", "a"); !errors.Is(err, sentinel) {
		t.Fatalf("Get error = %v, want sentinel", err)
	}
	if err := Delete("s", "a"); !errors.Is(err, sentinel) {
		t.Fatalf("Delete error = %v, want sentinel", err)
	}
}

func TestErrorString(t *testing.T) {
	e := &Error{Op: "get", Status: -25300}
	if got := e.Error(); got != "keychain: get: OSStatus -25300" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestBiometryTypeString(t *testing.T) {
	for _, tc := range []struct {
		b    BiometryType
		want string
	}{
		{BiometryNone, "None"},
		{BiometryTouchID, "TouchID"},
		{BiometryFaceID, "FaceID"},
		{BiometryOpticID, "OpticID"},
		{BiometryType(99), "None"},
	} {
		if got := tc.b.String(); got != tc.want {
			t.Errorf("BiometryType(%d).String() = %q, want %q", tc.b, got, tc.want)
		}
	}
}

func TestBiometryTypeFromRaw(t *testing.T) {
	for raw, want := range map[int64]BiometryType{
		0: BiometryNone,
		1: BiometryTouchID,
		2: BiometryFaceID,
		3: BiometryOpticID,
		7: BiometryNone,
	} {
		if got := biometryTypeFromRaw(raw); got != want {
			t.Errorf("biometryTypeFromRaw(%d) = %v, want %v", raw, got, want)
		}
	}
}

func TestMapLAError(t *testing.T) {
	for code, want := range map[int64]error{
		laErrAuthenticationFailed: ErrAuthenticationFailed,
		laErrUserCancel:           ErrUserCanceled,
		laErrSystemCancel:         ErrUserCanceled,
		laErrAppCancel:            ErrUserCanceled,
		laErrPasscodeNotSet:       ErrPasscodeNotSet,
		laErrBiometryNotAvailable: ErrBiometryNotAvailable,
		laErrBiometryNotEnrolled:  ErrBiometryNotEnrolled,
		laErrBiometryLockout:      ErrBiometryLockout,
	} {
		err := mapLAError(code)
		if !errors.Is(err, want) {
			t.Errorf("mapLAError(%d) = %v, want Is %v", code, err, want)
		}
		var le *LAError
		if !errors.As(err, &le) || le.Code != code {
			t.Errorf("mapLAError(%d) LAError.Code = %v, want %d", code, err, code)
		}
	}
}

func TestLAErrorUnclassified(t *testing.T) {
	err := mapLAError(-1234)
	var le *LAError
	if !errors.As(err, &le) || le.Code != -1234 {
		t.Fatalf("mapLAError(-1234) = %v, want *LAError{Code:-1234}", err)
	}
	if le.Unwrap() != nil {
		t.Fatalf("Unwrap() = %v, want nil for unclassified code", le.Unwrap())
	}
	if got, want := le.Error(), "keychain: LocalAuthentication error -1234"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	// A classified error renders the sentinel plus the raw code.
	if got, want := mapLAError(laErrUserCancel).Error(), "keychain: authentication canceled (LAError -2)"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestNewAuthContextLoadErr(t *testing.T) {
	sentinel := errors.New("nope")
	withFakeLA(t, sentinel, nil, nil, nil, nil)
	if _, err := NewAuthContext(0); !errors.Is(err, sentinel) {
		t.Fatalf("NewAuthContext load-err = %v, want sentinel", err)
	}
}

func TestNewAuthContextBackendErr(t *testing.T) {
	boom := errors.New("alloc failed")
	withFakeLA(t, nil,
		func(time.Duration) (uintptr, error) { return 0, boom },
		nil, nil, nil)
	if _, err := NewAuthContext(time.Minute); !errors.Is(err, boom) {
		t.Fatalf("NewAuthContext backend-err = %v, want boom", err)
	}
}

func TestAuthContextLifecycle(t *testing.T) {
	var gotReuse time.Duration
	var closed uintptr
	withFakeLA(t, nil,
		func(reuse time.Duration) (uintptr, error) { gotReuse = reuse; return 0x1234, nil },
		func(h uintptr) { closed = h },
		nil,
		func(h uintptr, reason string) error {
			if h != 0x1234 || reason != "unlock" {
				t.Errorf("backendAuthenticate(%#x,%q)", h, reason)
			}
			return nil
		})

	ac, err := NewAuthContext(30 * time.Second)
	if err != nil {
		t.Fatalf("NewAuthContext: %v", err)
	}
	if gotReuse != 30*time.Second {
		t.Fatalf("reuse passed = %v, want 30s", gotReuse)
	}
	if err := ac.Authenticate("unlock"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// Feed the handle to a Get and confirm it is threaded through.
	var gotHandle uintptr
	withFakeBackend(t, nil, nil,
		func(_, _ string, h uintptr) ([]byte, int32) { gotHandle = h; return []byte("v"), errSecSuccess },
		nil)
	if _, err := Get("s", "a", WithAuthContext(ac)); err != nil {
		t.Fatalf("Get(WithAuthContext): %v", err)
	}
	if gotHandle != 0x1234 {
		t.Fatalf("Get authCtx = %#x, want 0x1234", gotHandle)
	}

	ac.Close()
	if closed != 0x1234 {
		t.Fatalf("Close released %#x, want 0x1234", closed)
	}
	// Idempotent: a second Close is a no-op, and use after close fails.
	closed = 0
	ac.Close()
	if closed != 0 {
		t.Fatalf("second Close released %#x, want none", closed)
	}
	if err := ac.Authenticate("x"); !errors.Is(err, ErrAuthContextClosed) {
		t.Fatalf("Authenticate after Close = %v, want ErrAuthContextClosed", err)
	}
	if _, err := Get("s", "a", WithAuthContext(ac)); !errors.Is(err, ErrAuthContextClosed) {
		t.Fatalf("Get with closed ctx = %v, want ErrAuthContextClosed", err)
	}
}

func TestNilAuthContext(t *testing.T) {
	withFakeLA(t, nil, nil, nil, nil,
		func(uintptr, string) error { t.Fatal("backendAuthenticate called"); return nil })
	var ac *AuthContext
	ac.Close() // nil receiver: no panic, no-op
	if err := ac.Authenticate("x"); !errors.Is(err, ErrAuthContextClosed) {
		t.Fatalf("nil.Authenticate = %v, want ErrAuthContextClosed", err)
	}
	withFakeBackend(t, nil, nil,
		func(string, string, uintptr) ([]byte, int32) { t.Fatal("backendGet called"); return nil, 0 },
		nil)
	if _, err := Get("s", "a", WithAuthContext(nil)); !errors.Is(err, ErrAuthContextClosed) {
		t.Fatalf("Get(WithAuthContext(nil)) = %v, want ErrAuthContextClosed", err)
	}
}

func TestAuthContextAuthenticateLoadErr(t *testing.T) {
	sentinel := errors.New("down")
	withFakeLA(t, sentinel, nil, nil, nil, nil)
	ac := &AuthContext{handle: 1}
	if err := ac.Authenticate("x"); !errors.Is(err, sentinel) {
		t.Fatalf("Authenticate load-err = %v, want sentinel", err)
	}
}

func TestPackageAuthenticate(t *testing.T) {
	var gotHandle uintptr = 99
	withFakeLA(t, nil, nil, nil, nil,
		func(h uintptr, reason string) error {
			gotHandle = h
			if reason != "why" {
				t.Errorf("reason = %q", reason)
			}
			return ErrUserCanceled
		})
	if err := Authenticate("why"); !errors.Is(err, ErrUserCanceled) {
		t.Fatalf("Authenticate = %v, want ErrUserCanceled", err)
	}
	if gotHandle != 0 {
		t.Fatalf("package Authenticate handle = %#x, want 0 (throwaway)", gotHandle)
	}
}

func TestPackageAuthenticateLoadErr(t *testing.T) {
	sentinel := errors.New("x")
	withFakeLA(t, sentinel, nil, nil, nil, nil)
	if err := Authenticate("r"); !errors.Is(err, sentinel) {
		t.Fatalf("Authenticate load-err = %v, want sentinel", err)
	}
}

func TestCanEvaluate(t *testing.T) {
	withFakeLA(t, nil, nil, nil,
		func() (BiometryType, error) { return BiometryTouchID, nil }, nil)
	bt, err := CanEvaluate()
	if err != nil || bt != BiometryTouchID {
		t.Fatalf("CanEvaluate = (%v,%v), want (TouchID,nil)", bt, err)
	}
}

func TestCanEvaluateLoadErr(t *testing.T) {
	sentinel := errors.New("x")
	withFakeLA(t, sentinel, nil, nil, nil, nil)
	if bt, err := CanEvaluate(); !errors.Is(err, sentinel) || bt != BiometryNone {
		t.Fatalf("CanEvaluate load-err = (%v,%v), want (None,sentinel)", bt, err)
	}
}
