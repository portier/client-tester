package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	bin := flag.String("bin", "", "executable that runs the client")
	debug := flag.Bool("debug", false, "log all communication")
	flag.Parse()
	if *bin == "" {
		log.Fatal("-bin is required")
	}

	initSigner()
	initServer(sgn.keySet)
	initSubprocess(*bin, srv.origin)
	proc.debug = *debug

	var clientID string

	test("basic auth", func() {
		email := "john@example.com"

		proc.writeLine("auth", email)
		authURLStr := proc.expect("ok", "start authentication request")
		if authURLStr == "" {
			return
		}

		assert(
			strings.HasPrefix(authURLStr, authEndpoint+"?"),
			"auth URL points to the server auth endpoint",
		)
		authURL, err := url.Parse(authURLStr)
		if !assertOK(err, "auth URL is a valid URL") {
			return
		}

		params := authURL.Query()
		assertEq(params.Get("login_hint"), email, "login_hint is correct")
		assertEq(params.Get("scope"), "openid email", "scope is correct")
		assertEq(params.Get("response_type"), "id_token", "response_type is correct")

		redirectURI, err := url.Parse(params.Get("redirect_uri"))
		if !assertOK(err, "redirect_uri is a valid URL") ||
			!assert(redirectURI.IsAbs(), "redirect_uri is an absolute URL") {
			return
		}

		// Assume further test runs have the same client ID.
		clientID = fmt.Sprintf("%s://%s", redirectURI.Scheme, redirectURI.Host)
		assertEq(params.Get("client_id"), clientID, "client_id is the origin of redirect_uri")

		nonce := params.Get("nonce")
		assert(nonce != "", "nonce is not empty")

		now := time.Now().Unix()
		proc.writeLine("verify", sgn.simple(&payload{
			Iss:   srv.origin,
			Aud:   clientID,
			Exp:   now + 5,
			Iat:   now,
			Email: email,
			Nonce: nonce,
		}))
		verified := proc.expect("ok", "verify token request")
		assertEq(verified, email, "verified email matches input")
	})

	test("invalid issuer", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:   "http://eve.invalid",
				Aud:   clientID,
				Exp:   now + 5,
				Iat:   now,
				Email: email,
				Nonce: nonce,
			}))
			proc.expect("err", "rejects token")
		}
	})

	test("invalid audience", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:   srv.origin,
				Aud:   "http://eve.invalid",
				Exp:   now + 5,
				Iat:   now,
				Email: email,
				Nonce: nonce,
			}))
			proc.expect("err", "rejects token")
		}
	})

	test("expired token", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:   srv.origin,
				Aud:   clientID,
				Exp:   now - 10000,
				Iat:   now - 10020,
				Email: email,
				Nonce: nonce,
			}))
			proc.expect("err", "rejects token")
		}
	})

	test("expired token, but within leeway", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:   srv.origin,
				Aud:   clientID,
				Exp:   now - 30,
				Iat:   now - 50,
				Email: email,
				Nonce: nonce,
			}))
			proc.expect("ok", "accepts token")
		}
	})

	test("future issue time", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:   srv.origin,
				Aud:   clientID,
				Exp:   now + 10020,
				Iat:   now + 10000,
				Email: email,
				Nonce: nonce,
			}))
			proc.expect("err", "rejects token")
		}
	})

	test("future issue time, but within leeway", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:   srv.origin,
				Aud:   clientID,
				Exp:   now + 50,
				Iat:   now + 30,
				Email: email,
				Nonce: nonce,
			}))
			proc.expect("ok", "accepts token")
		}
	})

	test("unexpected email transform", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:   srv.origin,
				Aud:   clientID,
				Exp:   now + 5,
				Iat:   now,
				Email: "jane@example.com",
				Nonce: nonce,
			}))
			proc.expect("err", "rejects token")
		}
	})

	test("unexpected email_original transform", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:       srv.origin,
				Aud:       clientID,
				Exp:       now + 5,
				Iat:       now,
				Email:     email,
				EmailOrig: "jane@example.com",
				Nonce:     nonce,
			}))
			proc.expect("err", "rejects token")
		}
	})

	test("server normalization", func() {
		email := "İⅢ@İⅢ.example"
		normalized := "i̇ⅲ@xn--iiii-qwc.example"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:       srv.origin,
				Aud:       clientID,
				Exp:       now + 5,
				Iat:       now,
				Email:     normalized,
				EmailOrig: email,
				Nonce:     nonce,
			}))
			verified := proc.expect("ok", "verify token request")
			assertEq(verified, normalized, "verified email is normalized input")
		}
	})

	test("custom server normalization", func() {
		email := "john@example.com"
		normalized := "jane@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:       srv.origin,
				Aud:       clientID,
				Exp:       now + 5,
				Iat:       now,
				Email:     normalized,
				EmailOrig: email,
				Nonce:     nonce,
			}))
			verified := proc.expect("ok", "verify token request")
			assertEq(verified, normalized, "verified email is normalized input")
		}
	})

	test("invalid nonce", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.simple(&payload{
				Iss:   srv.origin,
				Aud:   clientID,
				Exp:   now + 5,
				Iat:   now,
				Email: email,
				Nonce: "definitely not something the client generates",
			}))
			proc.expect("err", "rejects token")
		}
	})

	test("invalid key ID", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.sign(sgn.priv, &header{
				KID: "bad key",
				Alg: alg,
			}, &payload{
				Iss:   srv.origin,
				Aud:   clientID,
				Exp:   now + 5,
				Iat:   now,
				Email: email,
				Nonce: nonce,
			}))
			proc.expect("err", "rejects token")
		}
	})

	test("bad signature", func() {
		email := "john@example.com"
		if nonce := quickStart(email); nonce != "" {
			now := time.Now().Unix()
			proc.writeLine("verify", sgn.sign(sgn.fake, &header{
				KID: kid,
				Alg: alg,
			}, &payload{
				Iss:   srv.origin,
				Aud:   clientID,
				Exp:   now + 5,
				Iat:   now,
				Email: email,
				Nonce: nonce,
			}))
			proc.expect("err", "rejects token")
		}
	})

	test("caching", func() {
		assertEq(srv.numConfigRequests, 1, "discovery requested just once")
		assertEq(srv.numKeysRequests, 1, "keys requested just once")
	})

	proc.stop()
	if !allOk {
		os.Exit(1)
	}
}
