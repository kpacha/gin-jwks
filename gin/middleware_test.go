package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"

	"github.com/kpacha/gin-jwks"
)

func TestToHTTPContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(ToHTTPContext())
	router.GET("/", func(c *gin.Context) {
		tok, ok := c.Get(JWTTokenContextKey)
		if !ok {
			t.Error("The token is not in the context")
			return
		}
		token, ok := tok.([]byte)
		if !ok {
			t.Error("The stored data is not a token")
			return
		}
		if string(token) != "something" {
			t.Errorf("unexpected token content. got: %s, want: something", string(token))
		}
		c.JSON(http.StatusOK, gin.H{"alive": true})
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER something")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	expected := "{\"alive\":true}"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

}

func TestAuth_noTokenInContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Auth(jwks.NoopVerifier))
	router.GET("/", func(c *gin.Context) {
		t.Error("This handler shouldn't be called")
		c.AbortWithStatus(http.StatusInternalServerError)
	})

	req, _ := http.NewRequest("GET", "/", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestAuth_noToken(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(JWTTokenContextKey, 42)
		c.Next()
	})
	router.Use(Auth(jwks.NoopVerifier))
	router.GET("/", func(c *gin.Context) {
		t.Error("This handler shouldn't be called")
		c.AbortWithStatus(http.StatusInternalServerError)
	})

	req, _ := http.NewRequest("GET", "/", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestAuth_wrongToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(JWTTokenContextKey, jwks.Token("token"))
		c.Next()
	})
	router.Use(Auth(jwks.ErrorVerifier))
	router.GET("/", func(c *gin.Context) {
		t.Error("This handler shouldn't be called")
		c.AbortWithStatus(http.StatusInternalServerError)
	})

	req, _ := http.NewRequest("GET", "/", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestAuth_ok(t *testing.T) {
	token := "something"
	expectedClaims := jwks.Claims{"aaa": "aaa"}
	verifier := func(tok jwks.Token, claims *jwks.Claims) error {
		if string(tok) != token {
			t.Errorf("the token passed by the mdw wasn't expect: got %s want %s",
				string(tok), token)
			return jwks.ErrUnverifiedMsg
		}
		*claims = expectedClaims
		return nil
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(JWTTokenContextKey, []byte(token))
		c.Next()
	})

	router.Use(Auth(verifier))
	router.GET("/", func(c *gin.Context) {
		cl, ok := c.Get(JWTClaimsContextKey)
		if !ok {
			t.Error("claims are not in the context")
			return
		}
		claims, ok := cl.(jwks.Claims)
		if !ok {
			t.Error("The stored claims are not claims")
			return
		}
		if len(claims) != len(expectedClaims) {
			t.Errorf("unexpected token content. got: %v, want: %v", claims, expectedClaims)
		}
		c.JSON(http.StatusOK, gin.H{"alive": true})
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER "+token)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	expected := "{\"alive\":true}"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

}

func TestVerify_noToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Verify(VerifyCfg{
		Verifier:       jwks.ErrorVerifier,
		ClaimsKey:      "none",
		TokenExtractor: AuthHeaderTokenExtractor,
	}))
	router.GET("/", func(c *gin.Context) {
		t.Error("This handler shouldn't be called")
		c.AbortWithStatus(http.StatusInternalServerError)
	})

	req, _ := http.NewRequest("GET", "/", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func BenchmarkVerify_okHS256(b *testing.B) {
	secret := []byte("secret")
	payload := []byte(`{"iss":"http://example.com/", "exp": 1515606371}`)
	token, err := jws.Sign(payload, jwa.HS256, secret)
	if err != nil {
		b.Error("Signature generated. got:", err.Error())
		return
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Verify(VerifyCfg{
		Verifier:       jwks.HS256Verifier(secret, "http://example.com/"),
		ClaimsKey:      "none",
		TokenExtractor: AuthHeaderTokenExtractor,
	}))
	router.GET("/", func(c *gin.Context) {
		c.Status(200)
	})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "bearer "+string(token))
		router.ServeHTTP(w, req)
		if w.Result().StatusCode != 200 {
			b.Error("wrong status code:", w.Result().StatusCode)
		}
	}
}

func BenchmarkVerify_koExpiredHS256(b *testing.B) {
	secret := []byte("secret")
	payload := []byte(`{"iss":"http://example.com/", "exp": 1515}`)
	token, err := jws.Sign(payload, jwa.HS256, secret)
	if err != nil {
		b.Error("Signature generated. got:", err.Error())
		return
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Verify(VerifyCfg{
		Verifier:       jwks.HS256Verifier(secret, "http://example.com/"),
		ClaimsKey:      "none",
		TokenExtractor: AuthHeaderTokenExtractor,
	}))
	router.GET("/", func(c *gin.Context) {
		b.Error("the handler shouldn't be executed")
		c.Status(200)
	})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "bearer "+string(token))
		router.ServeHTTP(w, req)
		if w.Result().StatusCode == 200 {
			b.Error("wrong status code:", w.Result().StatusCode)
		}
	}
}
