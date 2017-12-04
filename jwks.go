package jwks

import (
	"crypto/rsa"
	"fmt"
	"net/url"
	"strings"

	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-jwx/jwt"
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
	Verifier func(Token, *Claims) error
	// JWSVerifier is a function that verifies the received token
	JWSVerifier func(Token) ([]byte, error)
	// RSAVerifier is a function that verifies the received token against a public key
	RSAVerifier func(Token, *rsa.PublicKey) ([]byte, error)
	// JWKFetcher is a function that fetches the JWK set from the received path
	JWKFetcher func(string) (*jwk.Set, error)
	// RSAExtractor is a function that extracts a list of public keys from the received key set
	RSAExtractor func(*jwk.Set) ([]*rsa.PublicKey, error)
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
func Chain(vs []Verifier) Verifier {
	if len(vs) == 0 {
		return ErrorVerifier
	}
	return func(tok Token, claims *Claims) error {
		err := VerifierError{[]error{}}
		for _, v := range vs {
			errTmp := v(tok, claims)
			if errTmp == nil {
				return nil
			}
			err.Errors = append(err.Errors, errTmp)
		}
		return err
	}
}

// VerifierError is the error wrapping all the errors received from the chained verifiers
type VerifierError struct {
	Errors []error
}

// Error implements the error interface
func (v VerifierError) Error() string {
	msg := make([]string, len(v.Errors))
	for k, v := range v.Errors {
		msg[k] = v.Error()
	}
	return "all the chained validators failed: " + strings.Join(msg, "; ")
}

func verifier(issuer string, f JWSVerifier) Verifier {
	return func(tok Token, cs *Claims) error {
		verified, err := f(tok)
		if err != nil {
			return err
		}
		claims := jwt.NewClaimSet()

		if err := claims.UnmarshalJSON(verified); err != nil {
			return err
		}
		options := []jwt.VerifyOption{}
		if issuer != "" {
			options = append(options, jwt.WithIssuer(issuer))
		}
		if err := claims.Verify(options...); err != nil {
			return err
		}
		(*cs)["issuer"] = claims.Issuer
		if claims.NotBefore != nil {
			(*cs)["not_before"] = claims.NotBefore.Second()
		}
		(*cs)["audience"] = claims.Audience
		(*cs)["issued_at"] = claims.IssuedAt
		(*cs)["jwt_id"] = claims.JwtID
		(*cs)["subject"] = claims.Subject
		(*cs)["expiration"] = claims.Expiration
		(*cs)["private"] = claims.PrivateClaims
		if claims.EssentialClaims != nil {
			(*cs)["essential"] = map[string]interface{}{"audience": claims.EssentialClaims.Audience}
		}
		return nil
	}
}
