package firebaseJwtValidator

import (
	"net/http"
	"strings"
)

type TokenValidator struct {
	projectID          string
	headerValidator    HeaderValidator
	claimsValidator    ClaimsValidator
	signatureValidator SignatureValidator
}

func NewDefaultTokenValidator(projectID string) *TokenValidator {
	return NewTokenValidator(projectID,
		&DefaultHeaderValidator{},
		&DefaultClaimsValidator{},
		NewDefaultSignatureValidator(NewGoogleKeyFetcher(&http.Client{})))
}

func NewTokenValidator(projectID string, headerValidator HeaderValidator, claimsValidator ClaimsValidator, signatureValidator SignatureValidator) *TokenValidator {
	t := &TokenValidator{projectID: projectID, headerValidator: headerValidator, claimsValidator: claimsValidator, signatureValidator: signatureValidator}
	return t
}

func (tv *TokenValidator) Validate(token string) (bool, error) {
	split := strings.Split(token, ".")

	if len(split) != 3 {
		return false, ErrMalformedToken
	}

	header := split[0]
	claims := split[1]
	signature := split[2]

	if !tv.headerValidator.Validate(header) {
		return false, ErrHeaderValidationFailed
	}

	if !tv.claimsValidator.Validate(claims, tv.projectID) {
		return false, ErrClaimsValidationFailed
	}

	// We know this will succeed because the header validated
	_, h := decodeRawHeader(header)
	if !tv.signatureValidator.Validate(signature, h.Kid, header + "." + claims) {
		return false, ErrSignatureValidationFailed
	}

	return true, nil
}
