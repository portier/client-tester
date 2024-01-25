package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"log"

	"github.com/lestrrat-go/jwx/v2/jwk"
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

func initSigner() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("rsa.GenerateKey error:", err)
	}

	fake, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("rsa.GenerateKey error:", err)
	}

	key, err := jwk.FromRaw(priv.PublicKey)
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
	keySet.AddKey(key)

	log.Print("generated server RSA key")

	sgn = &signer{
		priv:   priv,
		fake:   fake,
		key:    key,
		keySet: keySet,
	}
}

func (sgn *signer) sign(key *rsa.PrivateKey, hdr *header, pl interface{}) string {
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
	case "none":
		// leave sign and err set to nil
	case "RS256":
		hash := sha256.Sum256([]byte(signed))
		sign, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	case "RS384":
		hash := sha512.Sum384([]byte(signed))
		sign, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA384, hash[:])
	case "RS512":
		hash := sha512.Sum512([]byte(signed))
		sign, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, hash[:])
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
	hdr := &header{
		KID: kid,
		Alg: alg,
	}
	return sgn.sign(sgn.priv, hdr, pl)
}
