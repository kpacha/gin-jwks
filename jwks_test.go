package jwks

import (
	"sync/atomic"
	"testing"
)

func TestChainVerfier_ko(t *testing.T) {
	var counter uint64
	v := func(tok Token, c *Claims) error {
		atomic.AddUint64(&counter, 1)
		return NoopVerifier(tok, c)
	}
	verifier := Chain([]Verifier{v, v, v, ErrorVerifier})
	if err := verifier([]byte{}, &Claims{}); err != ErrUnverifiedMsg {
		t.Error("unexpected error. got:", err)
		return
	}
	if counter != 3 {
		t.Error("unexpected execution count. got:", counter)
	}
}

func TestChainVerfier_ok(t *testing.T) {
	var counter uint64
	v := func(tok Token, c *Claims) error {
		atomic.AddUint64(&counter, 1)
		return NoopVerifier(tok, c)
	}
	verifier := Chain([]Verifier{v, v, v})
	if err := verifier([]byte{}, &Claims{}); err != nil {
		t.Error("unexpected error. got:", err.Error())
		return
	}
	if counter != 3 {
		t.Error("unexpected execution count. got:", counter)
	}
}
