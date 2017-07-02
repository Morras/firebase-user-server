package firebaseJwtValidator

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"time"
)

type ClaimsValidator interface {
	Validate(string, string) bool
}

const issuerPrefix = "https://securetoken.google.com/"

type claims struct {
	Aud, Iss, Sub string
	Exp, Iat      int64
}

func decodeRawClaims(raw string) (bool, claims) {
	jsonStr, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		log.Printf("Unable to validate claims due to input not being Base64 %v", raw)
		return false, claims{}
	}

	var c claims
	err = json.Unmarshal(jsonStr, &c)
	if err != nil {
		log.Printf("Unable to validate claims due to input not being valid json %v", string(jsonStr))
		return false, claims{}
	}
	return true, c
}

type DefaultClaimsValidator struct {
}

func (hv *DefaultClaimsValidator) Validate(raw string, projectID string) bool {
	success, c := decodeRawClaims(raw)
	if !success {
		return false
	}

	if c.Sub == "" {
		return false
	}

	now := time.Now().Unix()
	if c.Iat > now {
		log.Printf("Unable to validate claims as they are issued in the future %v > %v", c.Iat, now)
		return false
	}

	if c.Exp < now {
		log.Printf("Unable to validate claims as they are expired %v < %v", c.Exp, now)
		return false
	}

	if c.Iss != issuerPrefix+projectID {
		log.Printf("Unable to validate claims due to invalid issuer %v", c)
		return false
	}

	if c.Aud != projectID {
		log.Printf("Unable to validate claims due to invalid audience %v", c)
		return false
	}

	return true
}
