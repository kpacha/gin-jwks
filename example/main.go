package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kpacha/gin-jwks"
	ginjwks "github.com/kpacha/gin-jwks/gin"
)

func main() {
	jwkPath := flag.String("path", "", "path to the JWK file")
	issuer := flag.String("iss", "", "issuer of the JWT")
	flag.Parse()

	if *jwkPath == "" {
		log.Println("Error: a JWK path must be defined")
		return
	}

	if *issuer == "" {
		log.Println("Error: an issuer must be defined")
		return
	}

	verifier, err := jwks.RS256(*jwkPath, *issuer)
	if err != nil {
		log.Println("Error:", err.Error())
		return
	}

	router := gin.Default()

	router.Use(ginjwks.ToHTTPContext())
	router.Use(ginjwks.Auth(verifier))

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
