package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-jwx/jws"
)

func TestRS256Verfier_koFetch(t *testing.T) {
	expectedErr := fmt.Errorf("booom")
	config := DefaultRS256Config("jwkPath", "issuer")
	config.Fetcher = func(path string) (*jwk.Set, error) {
		return nil, expectedErr
	}
	if _, err := NewRS256Verifier(config); err != expectedErr {
		t.Error("Unexpected error. got:", err)
	}
}

func TestRS256Verfier_koExtract(t *testing.T) {
	expectedErr := fmt.Errorf("booom")
	config := DefaultRS256Config("", "")
	config.Fetcher = func(_ string) (*jwk.Set, error) {
		return nil, nil
	}
	config.Extractor = func(keySet *jwk.Set) ([]*rsa.PublicKey, error) {
		if keySet != nil {
			t.Error("expecting a null keySet")
		}
		return nil, expectedErr
	}
	if _, err := NewRS256Verifier(config); err != expectedErr {
		t.Error("Unexpected error. got:", err)
	}
}

func TestRS256Verfier_ok(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("RSA key generated: %s", err.Error())
		return
	}

	config := DefaultRS256Config("unknown", "issuer")
	config.Fetcher = func(path string) (*jwk.Set, error) {
		return nil, nil
	}
	config.Extractor = func(keySet *jwk.Set) ([]*rsa.PublicKey, error) {
		if keySet != nil {
			t.Error("expecting a null keySet")
		}
		return []*rsa.PublicKey{&key.PublicKey}, nil
	}
	if _, err := NewRS256Verifier(config); err != nil {
		t.Error("Unexpected error. got:", err)
	}
}

func TestExtractRS256PublickKeys(t *testing.T) {
	buff := []byte(`{"keys":
       [
          {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }`)
	set, err := jwk.Parse(buff)
	if err != nil {
		t.Error("Unexpected error. got:", err.Error())
	}
	keys, err := extractRS256PublickKeys(set)
	if err != nil {
		t.Error("Unexpected error. got:", err)
	}
	if len(keys) != 1 {
		t.Errorf("Unexpected number of keys. got: %d", len(keys))
	}
}

func TestExtractRS256PublickKeys_nil(t *testing.T) {
	keys, err := extractRS256PublickKeys(nil)
	if err != ErrNoSupportedKeys {
		t.Error("Unexpected error. got:", err)
	}
	if len(keys) != 0 {
		t.Errorf("Unexpected number of keys. got: %d", len(keys))
	}
}

func TestExtractRS256PublickKeys_empty(t *testing.T) {
	buff := []byte(`{"keys":[]}`)
	set, err := jwk.Parse(buff)
	if err != nil {
		t.Error("Unexpected error. got:", err.Error())
	}
	keys, err := extractRS256PublickKeys(set)
	if err != ErrNoSupportedKeys {
		t.Error("Unexpected error. got:", err)
	}
	if len(keys) != 0 {
		t.Errorf("Unexpected number of keys. got: %d", len(keys))
	}
}

func TestRS256Verify_ok(t *testing.T) {
	payload := []byte("{\"iss\":\"http://example.com/\"}")
	buf, key, err := sign(payload)
	if err != nil {
		t.Error("Signature generated. got:", err.Error())
		return
	}

	if err := RS256Verifier(key, "http://example.com/", rs256Verifier)(buf, &Claims{}); err != nil {
		t.Error("Verification error:", err.Error())
	}
}

func TestRS256Verify_empty(t *testing.T) {
	payload := []byte("")
	buf, key, err := sign(payload)
	if err != nil {
		t.Error("Signature generated. got:", err.Error())
		return
	}

	if err := RS256Verifier(key, "http://example.com/", rs256Verifier)(buf, &Claims{}); err == nil {
		t.Error("Verification error!")
	}
}

func TestRS256Verify_ko(t *testing.T) {
	payload := []byte("")
	buf, key, err := sign(payload)
	if err != nil {
		t.Error("Signature generated. got:", err.Error())
		return
	}

	expectedErr := fmt.Errorf("booom")
	verifier := func(tok Token, publicKey *rsa.PublicKey) ([]byte, error) {
		return []byte{}, expectedErr
	}

	if err := RS256Verifier(key, "http://example.com/", verifier)(buf, &Claims{}); err != expectedErr {
		t.Error("Verification error. got:", err)
	}
}

func TestRS256Verify_koBadIssuer(t *testing.T) {
	payload := []byte("{}")
	buf, key, err := sign(payload)
	if err != nil {
		t.Error("Signature generated. got:", err.Error())
		return
	}

	if err := RS256Verifier(key, "http://example.com/", rs256Verifier)(buf, &Claims{}); err == nil {
		t.Error("Verification error:", err)
	}
}

func TestRS256Verify_koExpired(t *testing.T) {
	payload := []byte(`{"iss":"http://example.com/", "exp": 123456}`)
	buf, key, err := sign(payload)
	if err != nil {
		t.Error("Signature generated. got:", err.Error())
		return
	}

	if err := RS256Verifier(key, "http://example.com/", rs256Verifier)(buf, &Claims{}); err == nil || err.Error() != "exp not satisfied" {
		t.Error("Verification error:", err)
	}
}

func sign(payload []byte) ([]byte, *rsa.PublicKey, error) {
	buf := []byte{}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return buf, nil, err
	}

	jwkkey, err := jwk.NewRsaPublicKey(&key.PublicKey)
	if err != nil {
		return buf, nil, err
	}
	jwkkey.Algorithm = jwa.RS256.String()

	buf, err = jws.Sign(payload, jwa.RS256, key)
	return buf, &key.PublicKey, err
}
