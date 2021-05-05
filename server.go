package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
)

const authEndpoint = "http://imaginary-server.test/fake-auth-route"

var srv *server

type discoveryDoc struct {
	JWKsURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

type server struct {
	origin            string
	numConfigRequests int
	numKeysRequests   int
}

func initServer(keys jwk.Set) {
	var origin string

	http.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, r *http.Request) {
		srv.numConfigRequests++
		body, err := json.Marshal(&discoveryDoc{
			JWKsURI:               fmt.Sprintf("%s/test-keys", origin),
			AuthorizationEndpoint: authEndpoint,
		})
		if err != nil {
			log.Fatal("json.Marshal error:", err)
		}
		rw.Write(body)
	})

	http.HandleFunc("/test-keys", func(rw http.ResponseWriter, r *http.Request) {
		srv.numKeysRequests++
		body, err := json.Marshal(keys)
		if err != nil {
			log.Fatal("json.Marshal error:", err)
		}
		rw.Write(body)
	})

	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		log.Fatal("net.Listen error:", err)
	}

	go func() {
		log.Fatal(http.Serve(listener, nil))
	}()

	origin = fmt.Sprintf("http://%s", listener.Addr().String())
	log.Print("started test server: ", origin)
	srv = &server{
		origin: origin,
	}
}
