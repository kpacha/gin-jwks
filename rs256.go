package jwks

import (
	"crypto/rsa"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"
)

// RS256 is the dafault factory for the RS256 JWK and JWS verifier
func RS256(jwkPath, issuer string) (Verifier, error) {
	return NewRS256Verifier(DefaultRS256Config(jwkPath, issuer))
}

// RS256Config stores the components to use in the verifier
type RS256Config struct {
	JWKPath   string
	Issuer    string
	Fetcher   JWKFetcher
	Extractor JWKExtractor
	Verifier  JWSVerifier
}

// DefaultRS256Config creates a RS256Config with the default components and the injected jwkPath and issuer
func DefaultRS256Config(jwkPath, issuer string) RS256Config {
	return RS256Config{
		JWKPath:   jwkPath,
		Issuer:    issuer,
		Fetcher:   DefaultJWKFetcher,
		Extractor: extractRS256PublickKeys,
		Verifier:  rs256Verifier,
	}
}

// NewRS256Verifier builds a verifier with the received configuration
func NewRS256Verifier(config RS256Config) (Verifier, error) {
	key, err := config.Fetcher(config.JWKPath)
	if err != nil {
		return NoopVerifier, err
	}
	keys, err := config.Extractor(key)
	if err != nil {
		return NoopVerifier, err
	}
	verifiers := []Verifier{}
	for _, key := range keys {
		verifiers = append(verifiers, RS256Verifier(key, config.Issuer, config.Verifier))
	}
	return Chain(verifiers), nil
}

// RS256Verifier is a single key varifier over a JWSVerifier
func RS256Verifier(publicKey *rsa.PublicKey, issuer string, verifier JWSVerifier) Verifier {
	return func(tok Token, cs *Claims) error {
		verified, err := verifier(tok, publicKey)
		if err != nil {
			return err
		}
		claims := jwt.NewClaimSet()

		if err := claims.UnmarshalJSON(verified); err != nil {
			return err
		}
		if err := claims.Verify(jwt.WithIssuer(issuer)); err != nil {
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

func rs256Verifier(tok Token, publicKey *rsa.PublicKey) ([]byte, error) {
	return jws.Verify(tok, jwa.RS256, publicKey)
}

func extractRS256PublickKeys(keySet *jwk.Set) ([]*rsa.PublicKey, error) {
	keys := []*rsa.PublicKey{}
	if keySet == nil {
		return keys, ErrNoSupportedKeys
	}
	for _, k := range keySet.Keys {
		if k.Alg() == string(jwa.RS256) {
			var publickey *rsa.PublicKey
			v, err := k.Materialize()
			if err != nil {
				continue
			}
			publickey = v.(*rsa.PublicKey)
			keys = append(keys, publickey)
		}
	}
	if len(keys) == 0 {
		return keys, ErrNoSupportedKeys
	}
	return keys, nil
}
