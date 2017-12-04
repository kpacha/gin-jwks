package jwks

import (
	"strings"
	"testing"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
)

func TestHS256Verify_ok(t *testing.T) {
	payload := []byte("{\"iss\":\"http://example.com/\"}")
	buf, err := jws.Sign(payload, jwa.HS256, []byte("secret"))
	if err != nil {
		t.Error("Signature generated. got:", err.Error())
		return
	}

	if err := HS256Verifier([]byte("secret"), "http://example.com/")(buf, &Claims{}); err != nil {
		t.Error("Verification error:", err.Error())
	}
}

func TestHS256Verify_empty(t *testing.T) {
	if err := HS256Verifier([]byte("secret"), "http://example.com/")([]byte(""), &Claims{}); err == nil {
		t.Error("Verification error!")
	}
}

func TestHS256Verify_ko(t *testing.T) {
	payload := []byte("")
	buf, err := jws.Sign(payload, jwa.HS256, []byte("secret"))
	if err != nil {
		t.Error("Signature generated. got:", err.Error())
		return
	}

	err = HS256Verifier([]byte("secret"), "http://example.com/")(buf, &Claims{})
	if err == nil || !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Error("Verification error. got:", err)
	}
}

func TestHS256Verify_koBadIssuer(t *testing.T) {
	payload := []byte("{}")
	buf, err := jws.Sign(payload, jwa.HS256, []byte("secret"))
	if err != nil {
		t.Error("Signature generated. got:", err.Error())
		return
	}

	if err := HS256Verifier([]byte("secret"), "http://example.com/")(buf, &Claims{}); err == nil {
		t.Error("Verification error:", err)
	}
}

func TestHS256Verify_koExpired(t *testing.T) {
	payload := []byte(`{"iss":"http://example.com/", "exp": 123456}`)
	buf, err := jws.Sign(payload, jwa.HS256, []byte("secret"))
	if err != nil {
		t.Error("Signature generated. got:", err.Error())
		return
	}

	if err = HS256Verifier([]byte("secret"), "http://example.com/")(buf, &Claims{}); err == nil || err.Error() != "exp not satisfied" {
		t.Error("Verification error:", err)
	}
}
