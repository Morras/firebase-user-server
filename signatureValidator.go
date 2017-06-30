package firebaseJwtValidator

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"log"
)

type KeyFetcher interface {
	FetchKey(kid string) (*rsa.PublicKey, error)
}

type SignatureValidator struct {
	keyFetcher KeyFetcher
}

func NewSignatureValidator(kf KeyFetcher) *SignatureValidator {
	return &SignatureValidator{keyFetcher: kf}
}

func (sv *SignatureValidator) Validate(signature string, params ValidatorParams) bool {

	publicKey, err := sv.keyFetcher.FetchKey(params.Kid)
	if err != nil {
		return false
	}

	decodedSig, err := base64.RawURLEncoding.DecodeString(signature)

	if err != nil {
		log.Printf("Unable to validate signature as input signature is invalid base64 %v, %v", err, []byte(signature))
		return false
	}

	hashed := sha256.Sum256([]byte(params.Message))

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], []byte(decodedSig))
	if err != nil {
		log.Printf("Error verifying signature %v for message %v with publicKey %v. Error was %v", signature, params.Message, publicKey, err)
		return false
	}
	return true
}
