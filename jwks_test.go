package jwks

import (
	"sync/atomic"
	"testing"
)

func TestChainVerfier_empty(t *testing.T) {
	verifier := Chain([]Verifier{})
	if err := verifier([]byte{}, &Claims{}); err != ErrUnverifiedMsg {
		t.Error("unexpected error. got:", err)
		return
	}
}

func TestChainVerfier_ko(t *testing.T) {
	expectedErrorMsg := "all the chained validators failed: failed to verify message; failed to verify message; failed to verify message; failed to verify message"
	var counter uint64
	v := func(tok Token, c *Claims) error {
		atomic.AddUint64(&counter, 1)
		return ErrorVerifier(tok, c)
	}
	verifier := Chain([]Verifier{v, v, v, ErrorVerifier})
	if err := verifier([]byte{}, &Claims{}); err == nil || err.Error() != expectedErrorMsg {
		t.Error("unexpected error. got:", err)
		return
	}
	if counter != 3 {
		t.Error("unexpected execution count. got:", counter)
	}
}

func TestChainVerfier_ok(t *testing.T) {
	var counter uint64
	vKo := func(tok Token, c *Claims) error {
		atomic.AddUint64(&counter, 1)
		return ErrorVerifier(tok, c)
	}
	vOk := func(tok Token, c *Claims) error {
		atomic.AddUint64(&counter, 1)
		return NoopVerifier(tok, c)
	}
	verifier := Chain([]Verifier{vKo, vKo, vOk})
	if err := verifier([]byte{}, &Claims{}); err != nil {
		t.Error("unexpected error. got:", err.Error())
		return
	}
	if counter != 3 {
		t.Error("unexpected execution count. got:", counter)
	}
}

func TestConcurrentVerfier_empty(t *testing.T) {
	verifier := Concurrent([]Verifier{})
	if err := verifier([]byte{}, &Claims{}); err != ErrUnverifiedMsg {
		t.Error("unexpected error. got:", err)
		return
	}
}

func TestConcurrentVerfier_ko(t *testing.T) {
	expectedErrorMsg := "all the chained validators failed: failed to verify message; failed to verify message; failed to verify message; failed to verify message"
	var counter uint64
	v := func(tok Token, c *Claims) error {
		atomic.AddUint64(&counter, 1)
		return ErrorVerifier(tok, c)
	}
	verifier := Concurrent([]Verifier{v, v, v, ErrorVerifier})
	if err := verifier([]byte{}, &Claims{}); err == nil || err.Error() != expectedErrorMsg {
		t.Error("unexpected error. got:", err)
		return
	}
	if counter != 3 {
		t.Error("unexpected execution count. got:", counter)
	}
}

func TestConcurrentVerfier_koSingle(t *testing.T) {
	expectedErrorMsg := "failed to verify message"
	verifier := Concurrent([]Verifier{ErrorVerifier})
	if err := verifier([]byte{}, &Claims{}); err == nil || err.Error() != expectedErrorMsg {
		t.Error("unexpected error. got:", err)
	}
}

func TestConcurrentVerfier_ok(t *testing.T) {
	vKo := func(tok Token, c *Claims) error {
		return ErrorVerifier(tok, c)
	}
	vOk := func(tok Token, c *Claims) error {
		return NoopVerifier(tok, c)
	}
	verifier := Concurrent([]Verifier{vKo, vKo, vOk})
	if err := verifier([]byte{}, &Claims{}); err != nil {
		t.Error("unexpected error. got:", err.Error())
		return
	}
}
