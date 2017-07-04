package firebaseJwtValidator_test

import (
	"strings"

	fjv "github.com/morras/firebaseJwtValidator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Section for setting up  mocks

type acceptHeaderValidator struct {
	Header string
}

func (ahv *acceptHeaderValidator) Validate(header string) bool {
	ahv.Header = header
	return true
}

type rejectHeaderValidator struct {
}

func (*rejectHeaderValidator) Validate(header string) bool {
	return false
}

type acceptClaimsValidator struct {
	Claims, ProjectID string
}

func (acv *acceptClaimsValidator) Validate(claims string, projectID string) bool {
	acv.Claims = claims
	acv.ProjectID = projectID
	return true
}

type rejectClaimsValidator struct {
}

func (r *rejectClaimsValidator) Validate(claims string, projectID string) bool {
	return false
}

type acceptSignatureValidator struct {
	Signature, Kid, Message string
}

func (asv *acceptSignatureValidator) Validate(signature string, kid string, message string) bool {
	asv.Signature = signature
	asv.Kid = kid
	asv.Message = message
	return true
}

type rejectSignatureValidator struct {
}

func (r *rejectSignatureValidator) Validate(signature string, kid string, message string) bool {
	return false
}

var _ = Describe("TokenValidator", func() {
	/*
		This is the example JWT this test will use
		Header:
		{
		  "alg": "HS256",
		  "kid": "472104712047"
		}
		Claims:
		{
		  "sub": "1234567890",
		  "name": "John Doe",
		  "admin": true
		}
	*/
	var validToken = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjQ3MjEwNDcxMjA0NyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.nTxXE3Kiond5qi_e0o0eqh-uZinGqUyOCiLz4i5858E"

	Context("with rejecting header validator", func() {
		tokenValidator := fjv.NewTokenValidator("project id", &rejectHeaderValidator{}, &acceptClaimsValidator{}, &acceptSignatureValidator{})
		It("should reject the validation", func() {
			result, err := tokenValidator.Validate(validToken)
			Expect(result).To(BeFalse())
			Expect(err).To(BeIdenticalTo(fjv.ErrHeaderValidationFailed))
		})
	})

	Context("with rejecting claims validator", func() {
		tokenValidator := fjv.NewTokenValidator("project id", &acceptHeaderValidator{}, &rejectClaimsValidator{}, &acceptSignatureValidator{})
		It("should reject the validation", func() {
			result, err := tokenValidator.Validate(validToken)
			Expect(result).To(BeFalse())
			Expect(err).To(BeIdenticalTo(fjv.ErrClaimsValidationFailed))
		})
	})

	Context("with rejecting signature validator", func() {
		tokenValidator := fjv.NewTokenValidator("project id", &acceptHeaderValidator{}, &acceptClaimsValidator{}, &rejectSignatureValidator{})
		It("should reject the validation", func() {
			result, err := tokenValidator.Validate(validToken)
			Expect(result).To(BeFalse())
			Expect(err).To(BeIdenticalTo(fjv.ErrSignatureValidationFailed))
		})
	})

	Context("with all accepting validators", func() {
		headerSpy := &acceptHeaderValidator{}
		claimsSpy := &acceptClaimsValidator{}
		signatureSpy := &acceptSignatureValidator{}
		tokenValidator := fjv.NewTokenValidator("project id", headerSpy, claimsSpy, signatureSpy)
		Context("and the input is valid", func() {
			It("should accept the validation", func() {
				result, err := tokenValidator.Validate(validToken)
				Expect(result).To(BeTrue())
				Expect(err).To(BeNil())
			})

			It("Should pass header part to header validator", func() {
				tokenValidator.Validate(validToken)
				Expect(headerSpy.Header).To(BeIdenticalTo("eyJhbGciOiJIUzI1NiIsImtpZCI6IjQ3MjEwNDcxMjA0NyJ9"))
			})

			It("Should pass claims part to header claims", func() {
				tokenValidator.Validate(validToken)
				Expect(claimsSpy.Claims).To(BeIdenticalTo("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"))
				Expect(claimsSpy.ProjectID).To(BeIdenticalTo("project id"))
			})

			It("Should pass signature part to signature validator", func() {
				tokenValidator.Validate(validToken)
				Expect(signatureSpy.Signature).To(BeIdenticalTo("nTxXE3Kiond5qi_e0o0eqh-uZinGqUyOCiLz4i5858E"))
				// This is the kid that is set in the header section of the valid token
				Expect(signatureSpy.Kid).To(BeIdenticalTo("472104712047"))
				split := strings.Split(validToken, ".")
				Expect(signatureSpy.Message).To(BeIdenticalTo(split[0] + "." + split[1]))
			})
		})

		Context("and input is having more than 2 dots", func() {
			It("should reject the validation", func() {
				result, err := tokenValidator.Validate("aaa.bbb.ccc.ddd")
				Expect(result).To(BeFalse())
				Expect(err).To(BeIdenticalTo(fjv.ErrMalformedToken))
			})
		})

		Context("and input is having less than 2 dots", func() {
			It("should reject the validation", func() {
				result, err := tokenValidator.Validate("aaa.bbb")
				Expect(result).To(BeFalse())
				Expect(err).To(BeIdenticalTo(fjv.ErrMalformedToken))
			})
		})
	})
})
