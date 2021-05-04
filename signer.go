package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/lestrrat-go/jwx/jwk"
)

const kid = "test key"
const alg = "RS256"

var sgn *signer

type signer struct {
	priv   *rsa.PrivateKey
	fake   *rsa.PrivateKey
	key    jwk.Key
	keySet jwk.Set
}

type header struct {
	KID string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
}

type payload struct {
	Iss       string `json:"iss,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Email     string `json:"email,omitempty"`
	EmailOrig string `json:"email_original,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}

func initSigner() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("rsa.GenerateKey error:", err)
	}

	fake, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("rsa.GenerateKey error:", err)
	}

	key, err := jwk.New(priv.PublicKey)
	if err != nil {
		log.Fatal("jwk.New error:", err)
	}

	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		log.Fatal("jwk.Key.Set error:", err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		log.Fatal("jwk.Key.Set error:", err)
	}

	keySet := jwk.NewSet()
	keySet.Add(key)

	log.Print("generated server RSA key")

	sgn = &signer{
		priv:   priv,
		fake:   fake,
		key:    key,
		keySet: keySet,
	}
}

func (sgn *signer) sign(key *rsa.PrivateKey, hdr *header, pl *payload) string {
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		log.Fatal("json.Marshal error:", err)
	}

	plJSON, err := json.Marshal(pl)
	if err != nil {
		log.Fatal("json.Marshal error:", err)
	}

	hdrEnc := base64.RawURLEncoding.EncodeToString(hdrJSON)
	plEnc := base64.RawURLEncoding.EncodeToString(plJSON)
	signed := hdrEnc + "." + plEnc

	hash := sha256.Sum256([]byte(signed))
	sign, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		log.Fatal("rsa.SignPKCS1v15 error:", err)
	}

	signEnc := base64.RawURLEncoding.EncodeToString(sign)
	return signed + "." + signEnc
}

func (sgn *signer) simple(pl *payload) string {
	hdr := &header{
		KID: kid,
		Alg: alg,
	}
	return sgn.sign(sgn.priv, hdr, pl)
}