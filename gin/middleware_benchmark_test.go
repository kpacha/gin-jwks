package gin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"

	"github.com/kpacha/gin-jwks"
)

func BenchmarkVerify_okChainnedHS256(b *testing.B) {
	secret := []byte("secret")
	vOk := jwks.HS256Verifier(secret, "http://example.com/")
	vKo := jwks.HS256Verifier([]byte("randomKey"), "http://example.com/")

	payload := []byte(`{"iss":"http://example.com/", "exp": 1515606371}`)
	token, err := jws.Sign(payload, jwa.HS256, secret)
	if err != nil {
		b.Error("Signature generated. got:", err.Error())
		return
	}

	gin.SetMode(gin.TestMode)

	for _, vs := range [][]jwks.Verifier{
		{vOk},
		{vKo, vOk},
		{vKo, vKo, vOk},
		{vKo, vKo, vKo, vOk},
		{vKo, vKo, vKo, vKo, vOk},
	} {
		b.Run(fmt.Sprintf("with %d verifiers", len(vs)), func(b *testing.B) {
			router := gin.New()
			router.Use(Verify(VerifyCfg{
				Verifier:       jwks.Chain(vs),
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
		})
	}
}

func BenchmarkVerify_okConcurrentHS256(b *testing.B) {
	secret := []byte("secret")
	vOk := jwks.HS256Verifier(secret, "http://example.com/")
	vKo := jwks.HS256Verifier([]byte("randomKey"), "http://example.com/")

	payload := []byte(`{"iss":"http://example.com/", "exp": 1515606371}`)
	token, err := jws.Sign(payload, jwa.HS256, secret)
	if err != nil {
		b.Error("Signature generated. got:", err.Error())
		return
	}

	gin.SetMode(gin.TestMode)

	for _, vs := range [][]jwks.Verifier{
		{vOk},
		{vKo, vOk},
		{vKo, vKo, vOk},
		{vKo, vKo, vKo, vOk},
		{vKo, vKo, vKo, vKo, vOk},
	} {
		b.Run(fmt.Sprintf("with %d verifiers", len(vs)), func(b *testing.B) {
			router := gin.New()
			router.Use(Verify(VerifyCfg{
				Verifier:       jwks.Concurrent(vs),
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
		})
	}
}

func BenchmarkVerify_okHS256_simple(b *testing.B) {
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
