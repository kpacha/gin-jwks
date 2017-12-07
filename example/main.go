package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/kpacha/gin-jwks"
	ginjwks "github.com/kpacha/gin-jwks/gin"
)

func main() {
	jwkPath := flag.String("path", "", "path to the JWK file")
	issuer := flag.String("iss", "", "issuer of the JWT")
	secret := flag.String("secret", "", "comma-separated list of HMAC secrets")
	flag.Parse()

	if *jwkPath == "" {
		log.Println("Error: a JWK path must be defined")
		return
	}

	if *secret == "" {
		log.Println("Error: a secret must be defined")
		return
	}

	jwks.DefaultGroupVerifier = jwks.Concurrent
	rsaVerifier, err := jwks.RS256(*jwkPath, *issuer)
	if err != nil {
		log.Println("Error:", err.Error())
		return
	}
	verifiers := []jwks.Verifier{rsaVerifier}

	for _, key := range strings.Split(*secret, ",") {
		verifiers = append(verifiers, jwks.HS256Verifier([]byte(key), *issuer))
	}

	router := gin.Default()

	router.Use(ginjwks.ToHTTPContext())
	router.Use(ginjwks.Auth(jwks.Concurrent(verifiers)))

	router.GET("/", func(c *gin.Context) {
		t, ok := c.Get(ginjwks.JWTTokenContextKey)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		token, ok := t.(jwks.Token)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		cl, ok := c.Get(ginjwks.JWTClaimsContextKey)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		claims, ok := cl.(jwks.Claims)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		c.JSON(http.StatusOK, gin.H{"token": token, "claims": claims})
	})

	router.Run(":8080")
}
