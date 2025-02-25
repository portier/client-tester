package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const rsaKID = "test key RSA"
const ed25519KID = "test key Ed25519"

var sgn *signer

type signer struct {
	alg        string
	rsaKey     *rsa.PrivateKey
	ed25519Key ed25519.PrivateKey
	rsaJwk     jwk.Key
	ed25519Jwk jwk.Key
	keySet     jwk.Set
}

type header struct {
	KID string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
}

func initSigner() {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("rsa.GenerateKey error:", err)
	}

	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("ed25519.GenerateKey error:", err)
	}

	rsaJwk, err := jwk.FromRaw(rsaKey.PublicKey)
	if err != nil {
		log.Fatal("jwk.New error:", err)
	}
	if err := rsaJwk.Set(jwk.KeyIDKey, rsaKID); err != nil {
		log.Fatal("jwk.Key.Set error:", err)
	}
	if err := rsaJwk.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		log.Fatal("jwk.Key.Set error:", err)
	}
	if err := rsaJwk.Set(jwk.KeyUsageKey, "sig"); err != nil {
		log.Fatal("jwk.Key.Set error:", err)
	}

	ed25519Jwk, err := jwk.FromRaw(ed25519Pub)
	if err != nil {
		log.Fatal("jwk.New error:", err)
	}
	if err := ed25519Jwk.Set(jwk.KeyIDKey, ed25519KID); err != nil {
		log.Fatal("jwk.Key.Set error:", err)
	}
	if err := ed25519Jwk.Set(jwk.AlgorithmKey, "EdDSA"); err != nil {
		log.Fatal("jwk.Key.Set error:", err)
	}
	if err := ed25519Jwk.Set(jwk.KeyUsageKey, "sig"); err != nil {
		log.Fatal("jwk.Key.Set error:", err)
	}

	keySet := jwk.NewSet()
	keySet.AddKey(rsaJwk)
	keySet.AddKey(ed25519Jwk)

	log.Print("generated server RSA key")

	sgn = &signer{
		alg:        "RS256",
		rsaKey:     rsaKey,
		ed25519Key: ed25519Priv,
		rsaJwk:     rsaJwk,
		ed25519Jwk: ed25519Jwk,
		keySet:     keySet,
	}
}

func (sgn *signer) sign(hdr *header, pl interface{}) string {
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

	var sign []byte
	switch hdr.Alg {
	case "RS256":
		hash := sha256.Sum256([]byte(signed))
		sign, err = rsa.SignPKCS1v15(rand.Reader, sgn.rsaKey, crypto.SHA256, hash[:])
	case "RS512":
		hash := sha512.Sum512([]byte(signed))
		sign, err = rsa.SignPKCS1v15(rand.Reader, sgn.rsaKey, crypto.SHA512, hash[:])
	case "EdDSA":
		sign = ed25519.Sign(sgn.ed25519Key, []byte(signed))
	default:
		log.Fatalf("alg '%s' not supported by signer", hdr.Alg)
	}
	if err != nil {
		log.Fatal("rsa.SignPKCS1v15 error:", err)
	}

	signEnc := base64.RawURLEncoding.EncodeToString(sign)
	return signed + "." + signEnc
}

func (sgn *signer) simple(pl interface{}) string {
	hdr := &header{Alg: sgn.alg}
	switch hdr.Alg {
	case "RS256":
		hdr.KID = rsaKID
	case "EdDSA":
		hdr.KID = ed25519KID
	default:
		log.Fatalf("alg '%s' not supported by signer", hdr.Alg)
	}
	return sgn.sign(hdr, pl)
}
