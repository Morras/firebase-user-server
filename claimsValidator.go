package firebaseJwtValidator

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"time"
)

// A ClaimsValidator validates the claims part of a JWT token.
type ClaimsValidator interface {
	// Validate determines whether the JWT claims are valid for a Firebase issued JWT when the projects id is projectID.
	// The claims are supplied in the base64 encoded value that is read directly from the JWT.
	Validate(claims string, projectID string) bool
}

const issuerPrefix = "https://securetoken.google.com/"

type claims struct {
	Aud, Iss, Sub string
	Exp, Iat      int64
}

// DecodeRawClaims decode Base64 encoded claims, but does no
// validation outside making sure it is valid Base64 and json.
func DecodeRawClaims(raw string) (bool, claims) {
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

// DefaultClaimsValidator implements the logic set out in the Firebase documentation to validate the JWT claims.
type DefaultClaimsValidator struct {
	// IATTolerance allows for some discrepancy between the time of the issuing server and the time of the validating service.
	iatTolerance int64
}

func NewDefaultClaimsValidator() *DefaultClaimsValidator {
	return &DefaultClaimsValidator{iatTolerance: 10}
}

// Validate returns true if the claims provided in the raw base64 encoded value from the JWT
// lives up to the requirements from Firebases documentation for a project with projectID as id.
//
// The rules are:
//   - Sub must exist and be non empty
//   - iat must not be after now
//   - exp must not be before now
//   - aud must be the same as projectID
//   - iss must be https://securetoken.google.com/<projectID>
func (hv *DefaultClaimsValidator) Validate(claims string, projectID string) bool {
	success, c := DecodeRawClaims(claims)
	if !success {
		return false
	}

	if c.Sub == "" {
		return false
	}

	now := time.Now().Unix()
	if c.Iat > now+hv.iatTolerance {
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
