package firebaseJwtValidator

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"log"
)

// A SignatureValidator validates the sugnature part of a JWT token.
type SignatureValidator interface {
	Validate(signature string, kid string, message string) bool
}

// The DefaultSignatureValidator uses a KeyFetcher to get the public key it
// tries to verify the signature with.
type DefaultSignatureValidator struct {
	keyFetcher KeyFetcher
}

// NewDefaultSignatureValidator creates a DefaultSignatureValidator that uses
// the supplie KeyFetcher to get the public key to verify the signature.
func NewDefaultSignatureValidator(kf KeyFetcher) *DefaultSignatureValidator {
	return &DefaultSignatureValidator{keyFetcher: kf}
}

// Validate determines if the signature supplied in its JWT base64 segment matches
// the signature of message using the public key with the id of kid.
func (sv *DefaultSignatureValidator) Validate(signature string, kid string, message string) bool {

	publicKey, err := sv.keyFetcher.FetchKey(kid)
	if err != nil {
		return false
	}

	decodedSig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		log.Printf("Unable to validate signature as input signature is invalid base64 %v, %v", err, []byte(signature))
		return false
	}

	hashed := sha256.Sum256([]byte(message))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], []byte(decodedSig))
	if err != nil {
		log.Printf("Error verifying signature %v for message %v with publicKey %v. Error was %v", signature, message, publicKey, err)
		return false
	}
	return true
}
