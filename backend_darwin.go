//go:build darwin

package keychain

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	pobjc "github.com/ebitengine/purego/objc"
	"github.com/go-macos/objc"
)

// This file binds the CoreFoundation + Security C APIs through purego (no cgo)
// and wires them into the OS-independent seams declared in keychain.go. The
// Keychain surface is plain C functions operating on CFDictionary/CFData — not
// Objective-C message sends — so it is reached with purego's dlsym/RegisterFunc
// directly (the go-macos/objc msgSend bridge does not apply); go-macos/objc is
// reused for the canonical framework paths.

// CoreFoundation string encoding for CFStringCreateWithCString.
const kCFStringEncodingUTF8 = 0x08000100

var (
	cfStringCreate      func(alloc uintptr, s string, enc uint32) uintptr
	cfDataCreate        func(alloc uintptr, bytes *byte, length int) uintptr
	cfDictCreateMutable func(alloc uintptr, capacity int, keyCB, valCB uintptr) uintptr
	cfDictSetValue      func(dict, key, value uintptr)
	cfRelease           func(cf uintptr)
	cfDataGetLength     func(data uintptr) int
	cfDataGetBytePtr    func(data uintptr) *byte

	secItemAdd          func(attrs uintptr, result *uintptr) int32
	secItemUpdate       func(query, attrs uintptr) int32
	secItemCopyMatching func(query uintptr, result *uintptr) int32
	secItemDelete       func(query uintptr) int32
	secACCreate         func(alloc, protection uintptr, flags uint, err *uintptr) uintptr

	// CFStringRef / CFBooleanRef constants (the exported symbol holds the ref).
	kSecClass                                    uintptr
	kSecClassGenericPassword                     uintptr
	kSecAttrService                              uintptr
	kSecAttrAccount                              uintptr
	kSecValueData                                uintptr
	kSecReturnData                               uintptr
	kSecMatchLimit                               uintptr
	kSecMatchLimitOne                            uintptr
	kSecAttrAccessControl                        uintptr
	kSecAttrAccessibleWhenUnlockedThisDeviceOnly uintptr
	kSecUseAuthenticationContext                 uintptr
	kCFBooleanTrue                               uintptr

	// Addresses of the dictionary callback structs (passed by pointer).
	kCFTypeDictionaryKeyCallBacks   uintptr
	kCFTypeDictionaryValueCallBacks uintptr
)

// LocalAuthentication framework path (go-macos/objc has no constant for it) and
// the LAPolicy values used by the Touch ID paths.
const (
	localAuthentication = "/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication"

	// laPolicyDeviceOwnerAuthenticationWithBiometrics requires a biometric
	// (Touch ID / Face ID); it does not fall back to the passcode.
	laPolicyDeviceOwnerAuthenticationWithBiometrics = 1
)

// laLoadErr records why the LocalAuthentication surface is unavailable, kept
// separate from backendLoadErr so a missing LA framework does not disable the
// plain Set/Get/Delete keychain paths. It is nil once LAContext resolves.
var laLoadErr error

func init() {
	load()
	loadLA()
	backendSet = realSet
	backendGet = realGet
	backendDelete = realDelete
	backendNewAuthContext = realNewAuthContext
	backendCloseAuthContext = realCloseAuthContext
	backendCanEvaluate = realCanEvaluate
	backendAuthenticate = realAuthenticate
}

// loadLA readies the LocalAuthentication surface: it inherits any core load
// failure, then dlopens Foundation (for NSString) and LocalAuthentication and
// confirms the LAContext class resolved. Failures land in laLoadErr only, so
// the keychain paths keep working without biometrics.
func loadLA() {
	if backendLoadErr != nil {
		laLoadErr = backendLoadErr
		return
	}
	if err := objc.Load(objc.Foundation, localAuthentication); err != nil {
		laLoadErr = fmt.Errorf("keychain: load LocalAuthentication: %w", err)
		return
	}
	if objc.GetClass("LAContext") == 0 {
		laLoadErr = errors.New("keychain: LAContext class unavailable")
	}
}

// newLAContext allocates and inits an LAContext (caller releases). It returns 0
// only on an unexpected allocation failure.
func newLAContext() objc.ID {
	return objc.ID(objc.GetClass("LAContext")).Send(objc.Sel("alloc")).Send(objc.Sel("init"))
}

// laErrorFromNSError reads the -[NSError code] and classifies it via
// mapLAError. A nil NSError (an unexpected "failed but no error" reply) is
// reported as a generic authentication failure.
func laErrorFromNSError(nsErr objc.ID) error {
	if nsErr == 0 {
		return ErrAuthenticationFailed
	}
	return mapLAError(objc.Send[int64](nsErr, objc.Sel("code")))
}

// realNewAuthContext is the darwin backendNewAuthContext: it allocates a
// retained LAContext and, when reuse > 0, sets its Touch ID reuse duration so a
// later evaluation within the window does not re-prompt.
func realNewAuthContext(reuse time.Duration) (uintptr, error) {
	if laLoadErr != nil {
		return 0, laLoadErr
	}
	ctx := newLAContext()
	if ctx == 0 {
		return 0, errors.New("keychain: LAContext init failed")
	}
	ctx = ctx.Send(objc.Sel("retain"))
	if reuse > 0 {
		ctx.Send(objc.Sel("setTouchIDAuthenticationAllowableReuseDuration:"), reuse.Seconds())
	}
	return uintptr(ctx), nil
}

// realCloseAuthContext is the darwin backendCloseAuthContext.
func realCloseAuthContext(handle uintptr) {
	if handle == 0 {
		return
	}
	objc.ID(handle).Send(objc.Sel("release"))
}

// realCanEvaluate is the darwin backendCanEvaluate. biometryType is only
// meaningful after canEvaluatePolicy:, so it probes first, then reads the type.
func realCanEvaluate() (BiometryType, error) {
	if laLoadErr != nil {
		return BiometryNone, laLoadErr
	}
	ctx := newLAContext()
	if ctx == 0 {
		return BiometryNone, errors.New("keychain: LAContext init failed")
	}
	defer ctx.Send(objc.Sel("release"))

	var nsErr objc.ID
	ok := objc.Send[bool](ctx, objc.Sel("canEvaluatePolicy:error:"),
		laPolicyDeviceOwnerAuthenticationWithBiometrics, &nsErr)
	bt := biometryTypeFromRaw(objc.Send[int64](ctx, objc.Sel("biometryType")))
	if !ok {
		return bt, laErrorFromNSError(nsErr)
	}
	return bt, nil
}

// realAuthenticate is the darwin backendAuthenticate. It drives
// evaluatePolicy:localizedReason:reply:, bridging the ObjC completion block
// (built with purego's NewBlock) to a Go channel so the call is synchronous.
// handle == 0 uses a throwaway context.
func realAuthenticate(handle uintptr, reason string) error {
	if laLoadErr != nil {
		return laLoadErr
	}
	if reason == "" {
		reason = "authenticate"
	}
	ctx := objc.ID(handle)
	if handle == 0 {
		ctx = newLAContext()
		if ctx == 0 {
			return errors.New("keychain: LAContext init failed")
		}
		defer ctx.Send(objc.Sel("release"))
	}

	res := make(chan error, 1)
	// reply is void(^)(BOOL success, NSError *error); purego reads the BOOL as
	// the low byte, so the bool parameter is the correct ABI here.
	block := pobjc.NewBlock(func(_ pobjc.Block, success bool, nsErr objc.ID) {
		if success {
			res <- nil
			return
		}
		res <- laErrorFromNSError(nsErr)
	})
	defer block.Release()

	ctx.Send(objc.Sel("evaluatePolicy:localizedReason:reply:"),
		laPolicyDeviceOwnerAuthenticationWithBiometrics, objc.NSString(reason), block)
	return <-res
}

// load resolves every CoreFoundation + Security symbol the backend needs,
// recording the first failure in backendLoadErr. A missing symbol on a
// supported macOS is not expected — these branches are defensive.
func load() {
	cf, err := purego.Dlopen(objc.CoreFoundation, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		backendLoadErr = fmt.Errorf("keychain: load CoreFoundation: %w", err)
		return
	}
	sec, err := purego.Dlopen(objc.Security, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		backendLoadErr = fmt.Errorf("keychain: load Security: %w", err)
		return
	}

	bind := func(fptr any, h uintptr, name string) {
		if backendLoadErr != nil {
			return
		}
		p, err := purego.Dlsym(h, name)
		if err != nil || p == 0 {
			backendLoadErr = fmt.Errorf("keychain: missing function %s", name)
			return
		}
		purego.RegisterFunc(fptr, p)
	}
	// A value symbol dereferences to the ref it holds (e.g. kSecClass).
	ref := func(h uintptr, name string) uintptr {
		if backendLoadErr != nil {
			return 0
		}
		p, err := purego.Dlsym(h, name)
		if err != nil || p == 0 {
			backendLoadErr = fmt.Errorf("keychain: missing symbol %s", name)
			return 0
		}
		return *(*uintptr)(unsafe.Pointer(p))
	}
	// A struct symbol is passed by its own address (the callback tables).
	addr := func(h uintptr, name string) uintptr {
		if backendLoadErr != nil {
			return 0
		}
		p, err := purego.Dlsym(h, name)
		if err != nil || p == 0 {
			backendLoadErr = fmt.Errorf("keychain: missing struct %s", name)
			return 0
		}
		return p
	}

	bind(&cfStringCreate, cf, "CFStringCreateWithCString")
	bind(&cfDataCreate, cf, "CFDataCreate")
	bind(&cfDictCreateMutable, cf, "CFDictionaryCreateMutable")
	bind(&cfDictSetValue, cf, "CFDictionarySetValue")
	bind(&cfRelease, cf, "CFRelease")
	bind(&cfDataGetLength, cf, "CFDataGetLength")
	bind(&cfDataGetBytePtr, cf, "CFDataGetBytePtr")
	bind(&secItemAdd, sec, "SecItemAdd")
	bind(&secItemUpdate, sec, "SecItemUpdate")
	bind(&secItemCopyMatching, sec, "SecItemCopyMatching")
	bind(&secItemDelete, sec, "SecItemDelete")
	bind(&secACCreate, sec, "SecAccessControlCreateWithFlags")

	kCFBooleanTrue = ref(cf, "kCFBooleanTrue")
	kCFTypeDictionaryKeyCallBacks = addr(cf, "kCFTypeDictionaryKeyCallBacks")
	kCFTypeDictionaryValueCallBacks = addr(cf, "kCFTypeDictionaryValueCallBacks")
	kSecClass = ref(sec, "kSecClass")
	kSecClassGenericPassword = ref(sec, "kSecClassGenericPassword")
	kSecAttrService = ref(sec, "kSecAttrService")
	kSecAttrAccount = ref(sec, "kSecAttrAccount")
	kSecValueData = ref(sec, "kSecValueData")
	kSecReturnData = ref(sec, "kSecReturnData")
	kSecMatchLimit = ref(sec, "kSecMatchLimit")
	kSecMatchLimitOne = ref(sec, "kSecMatchLimitOne")
	kSecAttrAccessControl = ref(sec, "kSecAttrAccessControl")
	kSecAttrAccessibleWhenUnlockedThisDeviceOnly = ref(sec, "kSecAttrAccessibleWhenUnlockedThisDeviceOnly")
	kSecUseAuthenticationContext = ref(sec, "kSecUseAuthenticationContext")
}

// cfStr makes a CFString from a Go string (caller releases).
func cfStr(s string) uintptr { return cfStringCreate(0, s, kCFStringEncodingUTF8) }

// newDict makes an empty mutable CFDictionary (caller releases).
func newDict() uintptr {
	return cfDictCreateMutable(0, 0, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks)
}

// baseQuery builds a mutable dictionary keyed to the (service, account)
// generic-password item. svc and acc are the caller-owned CFStrings.
func baseQuery(svc, acc uintptr) uintptr {
	d := newDict()
	cfDictSetValue(d, kSecClass, kSecClassGenericPassword)
	cfDictSetValue(d, kSecAttrService, svc)
	cfDictSetValue(d, kSecAttrAccount, acc)
	return d
}

// realSet is the darwin backendSet. With no access control it updates the
// item in place, adding it on first write; with access control it recreates
// the item behind a fresh SecAccessControl (an existing item cannot be
// updated to carry one, so it is deleted then re-added).
func realSet(service, account string, secret []byte, cfg config) int32 {
	svc, acc := cfStr(service), cfStr(account)
	defer cfRelease(svc)
	defer cfRelease(acc)
	data := cfDataCreate(0, &secret[0], len(secret))
	defer cfRelease(data)

	if cfg.useAC {
		del := baseQuery(svc, acc)
		secItemDelete(del)
		cfRelease(del)

		var acErr uintptr
		ac := secACCreate(0, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, uint(cfg.acFlags), &acErr)
		if ac == 0 {
			return errSecAccessControlFailed // defensive: creation only fails on bad flags
		}
		defer cfRelease(ac)

		add := baseQuery(svc, acc)
		defer cfRelease(add)
		cfDictSetValue(add, kSecValueData, data)
		cfDictSetValue(add, kSecAttrAccessControl, ac)
		return secItemAdd(add, nil)
	}

	query := baseQuery(svc, acc)
	defer cfRelease(query)
	upd := newDict()
	defer cfRelease(upd)
	cfDictSetValue(upd, kSecValueData, data)
	st := secItemUpdate(query, upd)
	if st == errSecItemNotFound {
		add := baseQuery(svc, acc)
		defer cfRelease(add)
		cfDictSetValue(add, kSecValueData, data)
		st = secItemAdd(add, nil)
	}
	return st
}

// realGet is the darwin backendGet. It copies the stored bytes into a
// Go-owned slice so nothing points at CoreFoundation-owned memory after the
// CFData is released. When authCtx is non-zero it is threaded to
// SecItemCopyMatching as kSecUseAuthenticationContext, so a Touch-ID-gated read
// reuses that LAContext's unlock window instead of prompting afresh.
func realGet(service, account string, authCtx uintptr) ([]byte, int32) {
	svc, acc := cfStr(service), cfStr(account)
	defer cfRelease(svc)
	defer cfRelease(acc)

	q := baseQuery(svc, acc)
	defer cfRelease(q)
	cfDictSetValue(q, kSecReturnData, kCFBooleanTrue)
	cfDictSetValue(q, kSecMatchLimit, kSecMatchLimitOne)
	if authCtx != 0 {
		cfDictSetValue(q, kSecUseAuthenticationContext, authCtx)
	}

	var result uintptr
	if st := secItemCopyMatching(q, &result); st != errSecSuccess {
		return nil, st
	}
	defer cfRelease(result)

	n := cfDataGetLength(result)
	out := make([]byte, n)
	if n > 0 { // n==0 is unreachable: Set rejects an empty secret
		copy(out, unsafe.Slice(cfDataGetBytePtr(result), n))
	}
	return out, errSecSuccess
}

// realDelete is the darwin backendDelete.
func realDelete(service, account string) int32 {
	svc, acc := cfStr(service), cfStr(account)
	defer cfRelease(svc)
	defer cfRelease(acc)
	q := baseQuery(svc, acc)
	defer cfRelease(q)
	return secItemDelete(q)
}
