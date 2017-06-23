package firebaseJwtValidator

import (
	"strings"
)

type ValidatorParams struct {
	ProjectId, Kid string
}

type Validator interface {
	Validate(string, ValidatorParams) bool
}

type TokenValidator struct {
	projectId          string
	headerValidator    Validator
	claimsValidator    Validator
	signatureValidator Validator
}

func NewTokenValidator(projectId string, headerValidator Validator, claimsValidator Validator, signatureValidator Validator) *TokenValidator {
	t := &TokenValidator{projectId: projectId, headerValidator: headerValidator, claimsValidator: claimsValidator, signatureValidator: signatureValidator}
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

	if !tv.headerValidator.Validate(header, ValidatorParams{}) {
		return false, ErrHeaderValidationFailed
	}

	if !tv.claimsValidator.Validate(claims, ValidatorParams{ProjectId: tv.projectId}) {
		return false, ErrClaimsValidationFailed
	}

	// We know this will succeed because the header validates
	_, h := decodeRawHeader(header)
	if !tv.signatureValidator.Validate(signature, ValidatorParams{Kid: h.Kid}) {
		return false, ErrSignatureValidationFailed
	}

	return true, nil
}
