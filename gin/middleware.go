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
		tok := c.Request.Header.Get("Authorization")
		if len(tok) > 6 && strings.ToUpper(tok[0:7]) == "BEARER " {
			c.Set(tokenKey, jwks.Token(tok[7:]))
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
	return func(c *gin.Context) {
		tok, ok := c.Get(tokenKey)
		if !ok {
			c.AbortWithError(http.StatusUnauthorized, ErrUnableToExtractToken)
			return
		}
		token, ok := tok.(jwks.Token)
		if !ok {
			c.AbortWithError(http.StatusUnauthorized, ErrUnableToExtractToken)
			return
		}
		claims := jwks.Claims{}
		if err := verifier(token, &claims); err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		c.Set(claimsKey, claims)
		c.Next()
	}
}
