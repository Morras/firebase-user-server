package firebaseJwtValidator_test

import (
	"crypto/rsa"

	"crypto/x509"
	"encoding/pem"
	fjv "github.com/Morras/firebaseJwtValidator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Section for setting up  mocks
type rejectingKeyFetcher struct{}

func (*rejectingKeyFetcher) FetchKey(kid string) (*rsa.PublicKey, error) {
	return nil, fjv.ErrNoSuchKey
}

type acceptingKeyFetcher struct {
	Input  string
	Output *rsa.PublicKey
}

func (a *acceptingKeyFetcher) FetchKey(kid string) (*rsa.PublicKey, error) {
	a.Input = kid
	return a.Output, nil
}

var _ = Describe("SignatureValidator", func() {

	publicKeyCert := "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIMHMF2XIvsTYwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcw\nNjI4MDA0NTI2WhcNMTcwNzAxMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAK3iQEzBq7quT/7g7kLNdu0EhFTxdELMq6n2Te1n5wGNtv5q\nelAxoe9WcZ5jBJe6KxfFD3TD7L4goAsNgdlGHOFACUarrBaUCKwb6f2Q26XHuVws\nMe5wBvwpfHQ3G4t12hO6k6IRbWG83cZaReQdOA+nN/F252QAABuw4pECFJasZa9y\nGzjG+37V2SZgBKToqeN5GYNgsbZsJTKYuLwsDSQUIW0IcOiugQy1wTQYU+Urnoz2\n3ABZF4U8tYyeI7W1ZOr+oU/BcjzOkGpbkApse1Ei5Ieyvm+Tz4pi6wmSja5qcKkL\nZc2Yt4ObzvaC2vza78J08yBd3cF/UAYLOxEVQS8CAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAEGe158vjJuMA6paKQo2v0Mxl+UMYFUfK4N2Fz0KhtFF\naKwILAFwpb2DYI6AhgtlCx/JsESivw49aeRignURi4TQAFzBdEVl9onCPJHWejZI\nOp1kSqZNjU2DA930bzA7HpkLQ+d5nvO5txQXxTNWww88a5oViwmHbRmnOGdEnb9x\nMGa65fY0SW7kPy5slJoh3WAtRDezWO23ZAodF5yR1esCtSADxknnOBns9wxGsjS9\nGlICEi9kRJjgHppNo+lWRP1tYcLiRzfmUr/IH3eJjNvSVgbmf4tk5Y0q/CSNIYdT\nC5+8lD4KRRXPzE5/XU2yOK/0DFL+SW3QXF0g9rsvBd0=\n-----END CERTIFICATE-----\n"
	block, _ := pem.Decode([]byte(publicKeyCert))
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	validSignature := "EVvSD9mw1Hu0w8GiTa0O7zLl-0_izdTB-kiJHRl2npSYL-JUM56iw9wJqfT01j2YOnTXVSRae-pnxXEuBP7HWIOQWpOOkiKeTlRHA72yJbBrQlbBASzvKp12pND2WZjefR7MLnlqDN9nWYJn3qvPotOPGFCmGK0iFS2O1rluOZlUmX2N4DZC_5M8eBPW_FEIXyhMGDJiTUv8NoPhfKlD4sC38AQDEcCoyPM5LoqtT4fnr6AtPRHLMY7kR_oidab-HTQcRl8RuDqN9frsAhrWmMMIvbV_5m5RUELc0CTNcgzifGab-bpFV1voKk4a4zMvsoSmJYITZiAVWQxcWafsEQ"
	headerPlusClaims := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhhMjJlOTQwZmEwYjAwNTBhN2E5MTBjOTRkM2YzNmVlNGM2OWEyZTQifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vbmV1dHJpbm8tMTE1MSIsIm5hbWUiOiJNb3J0ZW4gUmFzbXVzc2VuIiwicGljdHVyZSI6Imh0dHBzOi8vbGg2Lmdvb2dsZXVzZXJjb250ZW50LmNvbS8tdGZfUTFzY1hpeTgvQUFBQUFBQUFBQUkvQUFBQUFBQUFBSGMvTUY3SWlUZ1VyNkkvcGhvdG8uanBnIiwiYXVkIjoibmV1dHJpbm8tMTE1MSIsImF1dGhfdGltZSI6MTQ5ODY3ODk5MSwidXNlcl9pZCI6IjZ4cndSMURIb1lndmNWOUUwY3ZvUEt1cG12RTIiLCJzdWIiOiI2eHJ3UjFESG9ZZ3ZjVjlFMGN2b1BLdXBtdkUyIiwiaWF0IjoxNDk4Njc4OTkxLCJleHAiOjE0OTg2ODI1OTEsImVtYWlsIjoibS5yYXNtdXNzZW44NEBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJnb29nbGUuY29tIjpbIjEwNTE3NTgxNDY0ODYxNjMxMjM3NyJdLCJlbWFpbCI6WyJtLnJhc211c3Nlbjg0QGdtYWlsLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6Imdvb2dsZS5jb20ifX0"
	kid := "TestKid"

	// invalid base64
	var invalidBase64 = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwIiwgZm9vfQ="

	// valid base64 but invalid signature
	var invalidSignature = "eyJhbGciOiJSUzI1NiJ9"

	Context("Given a rejecting KeyFetcher", func() {
		signatureValidator := fjv.NewDefaultSignatureValidator(&rejectingKeyFetcher{})
		Context("And a valid input", func() {
			It("Should return false", func() {
				result := signatureValidator.Validate(validSignature, kid, headerPlusClaims)
				Expect(result).To(BeFalse())
			})
		})
	})

	Context("Given an accepting KeyFetcher", func() {
		spy := &acceptingKeyFetcher{Output: rsaPublicKey}
		signatureValidator := fjv.NewDefaultSignatureValidator(spy)

		It("Should call the key fetcher with key Id", func() {
			signatureValidator.Validate(validSignature, kid, headerPlusClaims)
			Expect(spy.Input).To(BeIdenticalTo("TestKid"))
		})

		Context("And the signature is valid", func() {
			It("Should return true", func() {
				result := signatureValidator.Validate(validSignature, kid, headerPlusClaims)
				Expect(result).To(BeTrue())
			})
		})

		Context("And the signature is invalid", func() {
			It("Should return true", func() {
				result := signatureValidator.Validate(invalidSignature, kid, headerPlusClaims)
				Expect(result).To(BeFalse())
			})
		})

		Context("And invalid encoded signature", func() {
			It("Should return false", func() {
				result := signatureValidator.Validate(invalidBase64, kid, headerPlusClaims)
				Expect(result).To(BeFalse())
			})
		})
	})
})
