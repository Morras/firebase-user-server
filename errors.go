package firebaseJwtValidator

import (
	"errors"
)

var ErrHeaderValidationFailed = errors.New("Header validation failed")
var ErrClaimsValidationFailed = errors.New("Claims validation failed")
var ErrSignatureValidationFailed = errors.New("Signature validation failed")
var ErrMalformedToken = errors.New("Token is malformed")
var ErrNoSuchKey = errors.New("No such key")
var ErrKeyServerConnectionFailed = errors.New("Unable to connect to the key server")
