package jwks

import (
	"crypto/rsa"
	"fmt"
	"net/url"

	"github.com/lestrrat/go-jwx/jwk"
)

var (
	// ErrNoSupportedKeys error returned when the JWK doesn't contain supported keys
	ErrNoSupportedKeys = fmt.Errorf("the JWK contained no supported keys")
	// ErrUnverifiedMsg error returned when the JWS verification fails
	ErrUnverifiedMsg = fmt.Errorf("failed to verify message")
)

type (
	// Claims is the structure that groups all the info regarding the token claims
	Claims map[string]interface{}
	// Token is the raw content of the JWT
	Token []byte

	// Verifier is a function that verifies the received token and stores the verified claims in the passed Claims
	Verifier func(tok Token, claims *Claims) error
	// JWSVerifier is a function that verifies the received token against a public key
	JWSVerifier func(tok Token, publicKey *rsa.PublicKey) ([]byte, error)
	// JWKFetcher is a function that fetches the JWK set from the received path
	JWKFetcher func(path string) (*jwk.Set, error)
	// JWKExtractor is a function that extracts a list of public keys from the received key set
	JWKExtractor func(keySet *jwk.Set) ([]*rsa.PublicKey, error)
)

// DefaultJWKFetcher implements the JWKFetcher interface. It is able to get JWK from the filesystem and network (http/https)
func DefaultJWKFetcher(path string) (*jwk.Set, error) {
	if u, err := url.Parse(path); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		return jwk.FetchHTTP(path)
	}
	return jwk.FetchFile(path)
}

// NoopVerifier is a dummy verifier that does nothing. Ideal for testing
func NoopVerifier(_ Token, _ *Claims) error { return nil }

// ErrorVerifier is a dummy verifier that always returns an ErrUnverifiedMsg error. Ideal for testing
func ErrorVerifier(_ Token, _ *Claims) error { return ErrUnverifiedMsg }

// Chain is a verifier that chains a set of verifiers, executing them with a FIFO strategy
func Chain(verifiers []Verifier) Verifier {
	if len(verifiers) == 0 {
		return ErrorVerifier
	}
	return func(tok Token, claims *Claims) error {
		for _, verifier := range verifiers {
			if err := verifier(tok, claims); err != nil {
				return err
			}
		}
		return nil
	}
}
