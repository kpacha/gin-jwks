package jwks

import (
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
)


// HS256Verifier is a single key verifier over a RSAVerifier
func HS256Verifier(secret []byte, issuer string) Verifier {
	return verifier(issuer, func(tok Token) ([]byte, error) {
		return jws.Verify(tok, jwa.HS256, secret)
	})
}