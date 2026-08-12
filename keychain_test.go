package keychain

import (
	"bytes"
	"errors"
	"testing"
)

// withFakeBackend swaps the package seams for test doubles and restores them
// afterwards, so the OS-independent logic in keychain.go is exercised on every
// platform without a live Keychain.
func withFakeBackend(t *testing.T, loadErr error, set func(string, string, []byte, config) int32, get func(string, string) ([]byte, int32), del func(string, string) int32) {
	t.Helper()
	origErr, origSet, origGet, origDel := backendLoadErr, backendSet, backendGet, backendDelete
	t.Cleanup(func() {
		backendLoadErr, backendSet, backendGet, backendDelete = origErr, origSet, origGet, origDel
	})
	backendLoadErr, backendSet, backendGet, backendDelete = loadErr, set, get, del
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
		func(string, string) ([]byte, int32) { return []byte("secret"), errSecSuccess },
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
		func(string, string) ([]byte, int32) { return nil, errSecItemNotFound },
		nil)
	if _, err := Get("svc", "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get error = %v, want ErrNotFound", err)
	}
}

func TestGetOtherError(t *testing.T) {
	withFakeBackend(t, nil, nil,
		func(string, string) ([]byte, int32) { return nil, -25293 },
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
		func(string, string) ([]byte, int32) { t.Fatal("backendGet called"); return nil, 0 },
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
