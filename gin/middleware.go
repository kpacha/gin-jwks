package gin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kpacha/gin-jwks"
)

const (
	// JWTTokenContextKey is the key for storing the token into the request context
	JWTTokenContextKey = "JWTToken"
	// JWTClaimsContextKey is the key for storing the claims into the request context
	JWTClaimsContextKey = "JWTClaims"
)

// ErrUnableToExtractToken is the error used when the token is not in the context
var ErrUnableToExtractToken = fmt.Errorf("unable to extract the JWT from the request")

// ToHTTPContext is a gin middleware that extracts the JWT from the http request and stores it
// in the request context, using the default key
func ToHTTPContext() gin.HandlerFunc { return ToHTTPContextWithKey(JWTTokenContextKey) }

// ToHTTPContextWithKey is a gin middleware that extracts the JWT from the http request and stores it
// in the request context, using the injected key
func ToHTTPContextWithKey(tokenKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if tok, ok := AuthHeaderTokenExtractor(c); ok {
			c.Set(tokenKey, tok)
		}
		c.Next()
	}
}

// Auth is a gin middleware that extracts the JWT from the default context location, verifies it
// and stores its claims in the request context, using the default key
func Auth(verifier jwks.Verifier) gin.HandlerFunc {
	return AuthWithKeys(verifier, JWTTokenContextKey, JWTClaimsContextKey)
}

// AuthWithKeys is a gin middleware that extracts the JWT from the injected context location, verifies it
// and stores its claims in the request context, using the received key
func AuthWithKeys(verifier jwks.Verifier, tokenKey, claimsKey string) gin.HandlerFunc {
	return Verify(VerifyCfg{
		Verifier:       verifier,
		TokenExtractor: ContextTokenExtractor(tokenKey),
		ClaimsKey:      claimsKey,
	})
}

// VerifyCfg defines a struct grouping all the params required for building the Verify middleware
type VerifyCfg struct {
	Verifier       jwks.Verifier
	TokenExtractor TokenExtractor
	ClaimsKey      string
}

// Verify creates a gin middleware that extracts the JWT with the injected token extractor, verifies it
// and stores its claims in the request context, using the defined claims key
func Verify(cfg VerifyCfg) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := ExtractVerifiedClaims(c, cfg.TokenExtractor, cfg.Verifier)
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		c.Set(cfg.ClaimsKey, *claims)
		c.Next()
	}
}

// TokenExtractor defines the interface to implement for the token extractor functions
type TokenExtractor func(*gin.Context) ([]byte, bool)

// ContextTokenExtractor returns a TokenExtractor that gets the token from the request context
func ContextTokenExtractor(tokenKey string) TokenExtractor {
	return func(c *gin.Context) (token []byte, ok bool) {
		tok, ok := c.Get(tokenKey)
		if !ok {
			return
		}
		token, ok = tok.([]byte)
		return
	}
}

// AuthHeaderTokenExtractor is a TokenExtractor that gets the token from the request Authorization header
func AuthHeaderTokenExtractor(c *gin.Context) (token []byte, ok bool) {
	tok := c.Request.Header.Get("Authorization")
	if len(tok) > 6 && strings.ToUpper(tok[0:7]) == "BEARER " {
		token = []byte(tok[7:])
		ok = true
	}
	return
}

// ExtractVerifiedClaims executes the token extractor and verifies the signature and the basic claims of the token
func ExtractVerifiedClaims(c *gin.Context, te TokenExtractor, verifier jwks.Verifier) (*jwks.Claims, error) {
	token, ok := te(c)
	if !ok {
		return nil, ErrUnableToExtractToken
	}
	claims := &jwks.Claims{}
	err := verifier(jwks.Token(token), claims)
	return claims, err
}
