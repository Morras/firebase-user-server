package firebaseJwtValidator

import (
	"encoding/base64"
	"encoding/json"
	"log"
)

const algorithm = "RS256"

// A HeaderValidator validates the claims part of a JWT token.
type HeaderValidator interface {
	// Validate determines whether the JWT header are valid for a Firebase issued JWT.
	// The Header are supplied in the base64 encoded value that is read directly from the JWT.
	Validate(header string) bool
}

// DefaultHeaderValidator implements the logic set out in the Firebase documentation to validate the JWT header.
type DefaultHeaderValidator struct {
}

type header struct {
	Kid, Alg string
}

func decodeRawHeader(raw string) (bool, header) {
	jsonStr, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		log.Printf("Unable to validate header due to input not being Base64 %v", raw)
		return false, header{}
	}

	var h header
	err = json.Unmarshal(jsonStr, &h)
	if err != nil {
		log.Printf("Unable to validate header due to input not being valid json %v", string(jsonStr))
		return false, header{}
	}
	return true, h
}

// Validate determines whether the JWT header are valid for a Firebase issued JWT.
// The Header are supplied in the base64 encoded value that is read directly from the JWT.
//
// The rules for header validation is that
//   - alg must be RS256
//   - kid must exist
func (hv *DefaultHeaderValidator) Validate(raw string) bool {
	success, h := decodeRawHeader(raw)
	if !success {
		return false
	}

	if h.Alg != algorithm {
		log.Printf("Unable to validate header due to invalid algorithm %v", h.Alg)
		return false
	}

	if h.Kid == "" {
		log.Printf("Unable to validate header due to missing kid value")
		return false
	}

	return true
}
