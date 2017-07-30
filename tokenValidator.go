package firebaseJwtValidator

import (
	"net/http"
	"strings"
)

// TokenValidator is a struct to hold validators used to validate
// a JWT against the rules set out by the Firebase project.
type TokenValidatorImpl struct {
	projectID          string
	headerValidator    HeaderValidator
	claimsValidator    ClaimsValidator
	signatureValidator SignatureValidator
}

type TokenValidator interface {
	Validate(token string) (bool, error)
}

// NewDefaultTokenValidator is the default token validator that validates using the
// DefaultHeaderValidator, DefaultClaimsValidator and DefaultSignatureValidator
// to validate a token against the rules set out by the Firebase projects documentation.
func NewDefaultTokenValidator(projectID string) TokenValidator {
	return NewTokenValidator(projectID,
		&DefaultHeaderValidator{},
		NewDefaultClaimsValidator(),
		NewDefaultSignatureValidator(NewCachedKeyFetcher(&http.Client{})))
}

// NewTokenValidator allows you to customize the TokenValidator by substituting
// validators for the individual JWT segments. See the validator interfaces
// for implementation details on the specific validators.
func NewTokenValidator(projectID string, headerValidator HeaderValidator, claimsValidator ClaimsValidator, signatureValidator SignatureValidator) TokenValidator {
	t := &TokenValidatorImpl{projectID: projectID, headerValidator: headerValidator, claimsValidator: claimsValidator, signatureValidator: signatureValidator}
	return t
}

// Validate a jwt token against the rules set out in the TokenValidators three validators.
// Return result of the validation and an error telling which part of the validation went
// wrong if the result is false.
func (tv *TokenValidatorImpl) Validate(token string) (bool, error) {
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
	if !tv.signatureValidator.Validate(signature, h.Kid, header+"."+claims) {
		return false, ErrSignatureValidationFailed
	}

	return true, nil
}
