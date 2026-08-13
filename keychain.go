// Package keychain is a pure-Go (CGO_ENABLED=0) store for macOS Keychain
// generic-password items. It reaches the OS through
// github.com/ebitengine/purego — dlsym'd CoreFoundation and Security C
// functions — so it links with no cgo and never shells out to
// /usr/bin/security (the secret never appears in any process's argv).
//
// The public surface is three byte-oriented calls over a (service, account)
// pair, each mapping to a kSecClassGenericPassword item:
//
//	err          := keychain.Set(service, account, secret)
//	secret, err  := keychain.Get(service, account)   // keychain.ErrNotFound if absent
//	err          := keychain.Delete(service, account)
//
// Errors are typed: [ErrNotFound] for a miss, [ErrEmptySecret] for an empty
// write, [ErrUnsupported] off darwin, and [*Error] (carrying the raw OSStatus)
// for any other Security-framework failure.
package keychain

import (
	"errors"
	"fmt"
	"time"
)

// OSStatus values from the Security framework that the package branches on.
const (
	errSecSuccess      int32 = 0
	errSecItemNotFound int32 = -25300
	// errSecAccessControlFailed is a synthetic status the darwin backend
	// returns when SecAccessControlCreateWithFlags yields nil (there is no
	// real OSStatus for that path — the failure is reported out-of-band).
	errSecAccessControlFailed int32 = -25291
)

// Sentinel errors. They are stable and may be compared with [errors.Is].
var (
	// ErrNotFound is returned by [Get] when no item exists for the
	// (service, account) pair.
	ErrNotFound = errors.New("keychain: item not found")
	// ErrEmptySecret is returned by [Set] when secret is empty; the Keychain
	// cannot hold a zero-length generic password and [Get] could not tell it
	// apart from a miss.
	ErrEmptySecret = errors.New("keychain: empty secret")
	// ErrUnsupported is returned by every entry point on non-darwin platforms
	// (the Keychain is macOS-only). Exported symbols exist everywhere so
	// consumers cross-compile.
	ErrUnsupported = errors.New("keychain: unsupported on this platform (darwin only)")

	// ErrAuthContextClosed is returned when an [AuthContext] is used after
	// [AuthContext.Close], or when a nil context is passed to [WithAuthContext].
	ErrAuthContextClosed = errors.New("keychain: AuthContext is closed")

	// LocalAuthentication (LAError) sentinels. A biometric operation
	// ([Authenticate], [CanEvaluate] or a Touch-ID-gated [Get]) reports one of
	// these via a wrapping [*LAError], comparable with [errors.Is]. Codes with
	// no dedicated sentinel surface as a bare [*LAError] carrying the raw code.
	//
	// ErrUserCanceled maps LAErrorUserCancel / SystemCancel / AppCancel — the
	// prompt was dismissed rather than failing.
	ErrUserCanceled = errors.New("keychain: authentication canceled")
	// ErrAuthenticationFailed maps LAErrorAuthenticationFailed — the presented
	// biometric did not match.
	ErrAuthenticationFailed = errors.New("keychain: authentication failed")
	// ErrBiometryNotAvailable maps LAErrorBiometryNotAvailable — no biometric
	// hardware, or the app is denied access to it.
	ErrBiometryNotAvailable = errors.New("keychain: biometry not available")
	// ErrBiometryNotEnrolled maps LAErrorBiometryNotEnrolled — hardware exists
	// but no fingerprint/face is enrolled.
	ErrBiometryNotEnrolled = errors.New("keychain: no biometric enrolled")
	// ErrBiometryLockout maps LAErrorBiometryLockout — too many failed attempts;
	// a passcode unlock is required to re-enable biometry.
	ErrBiometryLockout = errors.New("keychain: biometry locked out")
	// ErrPasscodeNotSet maps LAErrorPasscodeNotSet — a device passcode is
	// required for the policy but none is set.
	ErrPasscodeNotSet = errors.New("keychain: device passcode not set")
)

// BiometryType identifies the biometric hardware LocalAuthentication reports
// through -[LAContext biometryType] (valid only after a canEvaluatePolicy:
// probe, which [CanEvaluate] performs).
type BiometryType int

const (
	// BiometryNone means no biometric sensor is available (or none was
	// detected).
	BiometryNone BiometryType = iota
	// BiometryTouchID is a Touch ID fingerprint sensor.
	BiometryTouchID
	// BiometryFaceID is a Face ID camera.
	BiometryFaceID
	// BiometryOpticID is an Optic ID iris sensor.
	BiometryOpticID
)

// String renders the biometry type for logs and the demo.
func (b BiometryType) String() string {
	switch b {
	case BiometryTouchID:
		return "TouchID"
	case BiometryFaceID:
		return "FaceID"
	case BiometryOpticID:
		return "OpticID"
	default:
		return "None"
	}
}

// LAError wraps an NSError code from the LocalAuthentication framework. It
// unwraps to a sentinel (e.g. [ErrUserCanceled]) for the codes that have one,
// so both errors.Is(err, ErrUserCanceled) and inspection of the raw Code work.
type LAError struct {
	// Code is the raw LAError code (an NSInteger; the documented values are
	// negative, e.g. -2 for user cancel).
	Code int64
	// sentinel is the mapped sentinel, or nil for an unclassified code.
	sentinel error
}

// Error implements the error interface.
func (e *LAError) Error() string {
	if e.sentinel != nil {
		return fmt.Sprintf("%v (LAError %d)", e.sentinel, e.Code)
	}
	return fmt.Sprintf("keychain: LocalAuthentication error %d", e.Code)
}

// Unwrap exposes the mapped sentinel for [errors.Is].
func (e *LAError) Unwrap() error { return e.sentinel }

// Documented LAError codes (LAError.h). Only the ones with a dedicated sentinel
// are named here; any other code surfaces as a bare [*LAError].
const (
	laErrAuthenticationFailed int64 = -1
	laErrUserCancel           int64 = -2
	laErrSystemCancel         int64 = -4
	laErrPasscodeNotSet       int64 = -5
	laErrBiometryNotAvailable int64 = -6
	laErrBiometryNotEnrolled  int64 = -7
	laErrBiometryLockout      int64 = -8
	laErrAppCancel            int64 = -9
)

// mapLAError classifies a raw LAError code into an [*LAError], attaching a
// sentinel for the codes callers commonly branch on.
func mapLAError(code int64) error {
	var s error
	switch code {
	case laErrAuthenticationFailed:
		s = ErrAuthenticationFailed
	case laErrUserCancel, laErrSystemCancel, laErrAppCancel:
		s = ErrUserCanceled
	case laErrPasscodeNotSet:
		s = ErrPasscodeNotSet
	case laErrBiometryNotAvailable:
		s = ErrBiometryNotAvailable
	case laErrBiometryNotEnrolled:
		s = ErrBiometryNotEnrolled
	case laErrBiometryLockout:
		s = ErrBiometryLockout
	}
	return &LAError{Code: code, sentinel: s}
}

// biometryTypeFromRaw maps an -[LAContext biometryType] value to a
// [BiometryType].
func biometryTypeFromRaw(raw int64) BiometryType {
	switch raw {
	case 1:
		return BiometryTouchID
	case 2:
		return BiometryFaceID
	case 3:
		return BiometryOpticID
	default:
		return BiometryNone
	}
}

// Error wraps a non-success, non-not-found OSStatus from the Security
// framework, tagged with the operation that produced it.
type Error struct {
	// Op is the failing operation: "set", "get" or "delete".
	Op string
	// Status is the raw OSStatus returned by the Security framework.
	Status int32
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("keychain: %s: OSStatus %d", e.Op, e.Status)
}

// AccessControlFlags selects the SecAccessControlCreateFlags constraints an
// item created with [WithAccessControl] must satisfy on read. The zero value
// applies no interactive constraint (the item is readable whenever the
// accessibility class is satisfied, with no Touch ID / passcode prompt).
type AccessControlFlags uint

const (
	// UserPresence (kSecAccessControlUserPresence) gates every read behind
	// Touch ID or the device passcode. Reading such an item triggers the
	// system biometric prompt.
	UserPresence AccessControlFlags = 1 << 0
	// BiometryAny (kSecAccessControlBiometryAny) requires any currently
	// enrolled biometric.
	BiometryAny AccessControlFlags = 1 << 1
	// BiometryCurrentSet (kSecAccessControlBiometryCurrentSet) invalidates the
	// item if the enrolled biometric set changes.
	BiometryCurrentSet AccessControlFlags = 1 << 3
	// DevicePasscode (kSecAccessControlDevicePasscode) gates reads behind the
	// device passcode.
	DevicePasscode AccessControlFlags = 1 << 4
)

// config is the resolved set of [Option] values for a [Set].
type config struct {
	useAC   bool
	acFlags AccessControlFlags
}

// Option customises a [Set]. Options are applied left to right.
type Option func(*config)

// WithAccessControl stores the item behind a SecAccessControl protecting it
// with the given flags and the accessibility class
// kSecAttrAccessibleWhenUnlockedThisDeviceOnly (so it never leaves this
// device and is never synced to iCloud). Pass [UserPresence] to gate reads
// behind Touch ID or the passcode; pass 0 for an at-rest-protected item with
// no interactive prompt. Without this option an item is a plain generic
// password created (or updated in place) with the default accessibility.
func WithAccessControl(flags AccessControlFlags) Option {
	return func(c *config) {
		c.useAC = true
		c.acFlags = flags
	}
}

// Backend seams. They are assigned in an init(): on darwin (backend_darwin.go)
// to the real purego-backed implementations, elsewhere (backend_other.go) to
// unsupported stubs. Keeping the raw FFI behind these vars lets the
// OS-independent logic below reach full coverage on every lane — tests swap
// the seams for fakes to drive each branch without a live Keychain.
var (
	// backendLoadErr is non-nil when the backend could not initialise
	// (framework/symbol load failure, or a non-darwin platform).
	backendLoadErr error
	// backendSet writes secret for (service, account) per cfg and returns an
	// OSStatus.
	backendSet func(service, account string, secret []byte, cfg config) int32
	// backendGet reads the secret for (service, account), returning the bytes
	// and an OSStatus. authCtx is the LAContext handle from an [AuthContext]
	// (0 for none); when set it is passed to SecItemCopyMatching as
	// kSecUseAuthenticationContext so a Touch-ID-gated read reuses that context.
	backendGet func(service, account string, authCtx uintptr) ([]byte, int32)
	// backendDelete removes the item for (service, account) and returns an
	// OSStatus.
	backendDelete func(service, account string) int32

	// backendNewAuthContext allocates an LAContext with the given Touch ID
	// reuse duration and returns its handle.
	backendNewAuthContext func(reuse time.Duration) (uintptr, error)
	// backendCloseAuthContext releases the LAContext behind handle.
	backendCloseAuthContext func(handle uintptr)
	// backendCanEvaluate probes canEvaluatePolicy: and reports the biometry
	// type (and any reason it cannot evaluate).
	backendCanEvaluate func() (BiometryType, error)
	// backendAuthenticate runs evaluatePolicy: on the LAContext behind handle
	// (0 = a throwaway context), blocking until the reply block fires.
	backendAuthenticate func(handle uintptr, reason string) error
)

// Set stores secret under the generic-password item identified by
// (service, account), replacing any existing value. An empty secret is
// rejected with [ErrEmptySecret]. On a non-darwin platform it returns
// [ErrUnsupported].
func Set(service, account string, secret []byte, opts ...Option) error {
	if backendLoadErr != nil {
		return backendLoadErr
	}
	if len(secret) == 0 {
		return ErrEmptySecret
	}
	var c config
	for _, o := range opts {
		o(&c)
	}
	if st := backendSet(service, account, secret, c); st != errSecSuccess {
		return &Error{Op: "set", Status: st}
	}
	return nil
}

// getConfig is the resolved set of [GetOption] values for a [Get].
type getConfig struct {
	authCtx   uintptr
	ctxClosed bool
}

// GetOption customises a [Get]. Options are applied left to right.
type GetOption func(*getConfig)

// WithAuthContext makes [Get] read through ac's [AuthContext], so a
// Touch-ID-gated item ([WithAccessControl] + a biometric flag) prompts once and
// then, within the context's reuse window, is read again without re-prompting.
// Passing a nil or already-closed context makes the [Get] fail with
// [ErrAuthContextClosed].
func WithAuthContext(ac *AuthContext) GetOption {
	return func(g *getConfig) {
		if ac == nil || ac.closed {
			g.ctxClosed = true
			return
		}
		g.authCtx = ac.handle
	}
}

// Get returns the secret stored under (service, account). It returns
// [ErrNotFound] when no such item exists and [ErrUnsupported] off darwin.
// Reading an item created with [WithAccessControl] and [UserPresence] (or a
// biometric flag) triggers the system biometric prompt; pass [WithAuthContext]
// to reuse a single unlock across several reads.
func Get(service, account string, opts ...GetOption) ([]byte, error) {
	if backendLoadErr != nil {
		return nil, backendLoadErr
	}
	var g getConfig
	for _, o := range opts {
		o(&g)
	}
	if g.ctxClosed {
		return nil, ErrAuthContextClosed
	}
	b, st := backendGet(service, account, g.authCtx)
	switch st {
	case errSecSuccess:
		return b, nil
	case errSecItemNotFound:
		return nil, ErrNotFound
	default:
		return nil, &Error{Op: "get", Status: st}
	}
}

// Delete removes the item identified by (service, account). Deleting an
// absent item is not an error. It returns [ErrUnsupported] off darwin.
func Delete(service, account string) error {
	if backendLoadErr != nil {
		return backendLoadErr
	}
	if st := backendDelete(service, account); st != errSecSuccess && st != errSecItemNotFound {
		return &Error{Op: "delete", Status: st}
	}
	return nil
}

// AuthContext wraps a LocalAuthentication LAContext so a single Touch ID unlock
// can be reused across several reads. Create one with [NewAuthContext], pass it
// to [Get] via [WithAuthContext], and release it with [Close]. It is not safe
// for concurrent use across goroutines. The zero value is not usable.
type AuthContext struct {
	// handle is the retained LAContext object (an ObjC id as a uintptr on
	// darwin); 0 once closed or off darwin.
	handle uintptr
	closed bool
}

// NewAuthContext allocates an LAContext whose successful biometric evaluation
// is reusable for the given duration: after one unlock, a Touch-ID-gated [Get]
// made through this context (see [WithAuthContext]) within reuse does not
// re-prompt. A zero or negative reuse prompts on every read. The caller must
// [Close] the returned context. Off darwin it returns [ErrUnsupported].
func NewAuthContext(reuse time.Duration) (*AuthContext, error) {
	if backendLoadErr != nil {
		return nil, backendLoadErr
	}
	h, err := backendNewAuthContext(reuse)
	if err != nil {
		return nil, err
	}
	return &AuthContext{handle: h}, nil
}

// Close releases the underlying LAContext. It is idempotent and safe on a nil
// receiver. After Close the context must not be used again.
func (a *AuthContext) Close() {
	if a == nil || a.closed {
		return
	}
	a.closed = true
	backendCloseAuthContext(a.handle)
	a.handle = 0
}

// Authenticate presents the biometric prompt for this context (reusing its
// unlock window) with reason as the localized explanation, blocking until the
// user responds. It returns nil on success or a wrapping [*LAError] otherwise
// (compare with [errors.Is] against [ErrUserCanceled], [ErrAuthenticationFailed],
// …). It fails with [ErrAuthContextClosed] on a closed or nil context.
func (a *AuthContext) Authenticate(reason string) error {
	if backendLoadErr != nil {
		return backendLoadErr
	}
	if a == nil || a.closed {
		return ErrAuthContextClosed
	}
	return backendAuthenticate(a.handle, reason)
}

// CanEvaluate reports whether device-owner biometric authentication is
// currently possible and which [BiometryType] the hardware offers. When
// evaluation is not possible it returns the detected type together with a
// wrapping [*LAError] explaining why (e.g. [ErrBiometryNotEnrolled]). Off
// darwin it returns [ErrUnsupported].
func CanEvaluate() (BiometryType, error) {
	if backendLoadErr != nil {
		return BiometryNone, backendLoadErr
	}
	return backendCanEvaluate()
}

// Authenticate presents the system biometric prompt with reason as the
// localized explanation and blocks until the user responds, using a throwaway
// LAContext (no reuse). It returns nil on success or a wrapping [*LAError]
// otherwise. For reuse across reads, prefer [NewAuthContext] +
// [AuthContext.Authenticate] / [WithAuthContext]. Off darwin it returns
// [ErrUnsupported].
func Authenticate(reason string) error {
	if backendLoadErr != nil {
		return backendLoadErr
	}
	return backendAuthenticate(0, reason)
}
