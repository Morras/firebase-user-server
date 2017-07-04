package firebaseJwtValidator

import (
	"errors"
)

// ErrHeaderValidationFailed indicates that something went wrong when validating the JWT header.
// It should be possible to find specific information about the error in the logs.
var ErrHeaderValidationFailed = errors.New("Header validation failed")

// ErrClaimsValidationFailed indicates that something went wrong when validating the JWT claims.
// It should be possible to find specific information about the error in the logs.
var ErrClaimsValidationFailed = errors.New("Claims validation failed")

// ErrSignatureValidationFailed indicates that something went wrong when validating the JWT signature.
// It should be possible to find specific information about the error in the logs.
var ErrSignatureValidationFailed = errors.New("Signature validation failed")

// ErrMalformedToken indicates that the JWT is malformed and could not be parsed.
// It should be possible to find specific information about the error in the logs.
var ErrMalformedToken = errors.New("Token is malformed")

// ErrNoSuchKey indicates that the public key to verify the signature was not present in the response from Google key server.
// It should be possible to find specific information about the error in the logs.
var ErrNoSuchKey = errors.New("No such key")

// ErrKeyServerConnectionFailed indicates that something went wrong when getting the data from Googles key server.
// It should be possible to find specific information about the error in the logs.
var ErrKeyServerConnectionFailed = errors.New("Unable to connect to the key server")
