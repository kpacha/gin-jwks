package jwks

import (
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"
)

// HS256Verifier is a single key verifier over a RSAVerifier
func HS256Verifier(secret []byte, issuer string) Verifier {
	return func(tok Token, cs *Claims) error {
		verified, err := jws.Verify(tok, jwa.HS256, secret)
		if err != nil {
			return err
		}
		claims := jwt.NewClaimSet()

		if err := claims.UnmarshalJSON(verified); err != nil {
			return err
		}
		if issuer != "" {
			if err := claims.Verify(jwt.WithIssuer(issuer)); err != nil {
				return err
			}
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
