package firebaseJwtValidator_test

import (
	fjw "github.com/morras/firebaseJwtValidator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type acceptValidator struct {
}

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

func (*acceptValidator) Validate(input string, params fjw.ValidatorParams) bool {
	return true
}

type rejectValidator struct {
}

func (r *rejectValidator) Validate(input string, params fjw.ValidatorParams) bool {
	return false
}

type spyValidator struct {
	Input  string
	Params fjw.ValidatorParams
}

func (spy *spyValidator) Validate(input string, params fjw.ValidatorParams) bool {
	spy.Input = input
	spy.Params = params
	return true
}

var _ = Describe("TokenValidator", func() {
	Context("with rejecting header validator", func() {
		tokenValidator := fjw.NewTokenValidator("project id", &rejectValidator{}, &acceptValidator{}, &acceptValidator{})
		It("should reject the validation", func() {
			result, err := tokenValidator.Validate(validToken)
			Expect(result).To(BeFalse())
			Expect(err).To(BeIdenticalTo(fjw.ErrHeaderValidationFailed))
		})
	})

	Context("with rejecting claims validator", func() {
		tokenValidator := fjw.NewTokenValidator("project id", &acceptValidator{}, &rejectValidator{}, &acceptValidator{})
		It("should reject the validation", func() {
			result, err := tokenValidator.Validate(validToken)
			Expect(result).To(BeFalse())
			Expect(err).To(BeIdenticalTo(fjw.ErrClaimsValidationFailed))
		})
	})

	Context("with rejecting signature validator", func() {
		tokenValidator := fjw.NewTokenValidator("project id", &acceptValidator{}, &acceptValidator{}, &rejectValidator{})
		It("should reject the validation", func() {
			result, err := tokenValidator.Validate(validToken)
			Expect(result).To(BeFalse())
			Expect(err).To(BeIdenticalTo(fjw.ErrSignatureValidationFailed))
		})
	})

	Context("with all accepting validators", func() {
		headerSpy := &spyValidator{}
		claimsSpy := &spyValidator{}
		signatureSpy := &spyValidator{}
		tokenValidator := fjw.NewTokenValidator("project id", headerSpy, claimsSpy, signatureSpy)
		Context("and the input is valid", func() {
			It("should accept the validation", func() {
				result, err := tokenValidator.Validate(validToken)
				Expect(result).To(BeTrue())
				Expect(err).To(BeNil())
			})

			It("Should pass header part to header validator", func() {
				tokenValidator.Validate(validToken)
				Expect(headerSpy.Input).To(BeIdenticalTo("eyJhbGciOiJIUzI1NiIsImtpZCI6IjQ3MjEwNDcxMjA0NyJ9"))
			})

			It("Should pass claims part to header claims", func() {
				tokenValidator.Validate(validToken)
				Expect(claimsSpy.Input).To(BeIdenticalTo("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"))
				Expect(claimsSpy.Params.ProjectId).To(BeIdenticalTo("project id"))
			})

			It("Should pass signature part to signature validator", func() {
				tokenValidator.Validate(validToken)
				Expect(signatureSpy.Input).To(BeIdenticalTo("nTxXE3Kiond5qi_e0o0eqh-uZinGqUyOCiLz4i5858E"))
				// This is the kid that is set in the header section of the valid token
				Expect(signatureSpy.Params.Kid).To(BeIdenticalTo("472104712047"))
			})
		})

		Context("and input is having more than 2 dots", func() {
			It("should reject the validation", func() {
				result, err := tokenValidator.Validate("aaa.bbb.ccc.ddd")
				Expect(result).To(BeFalse())
				Expect(err).To(BeIdenticalTo(fjw.ErrMalformedToken))
			})
		})

		Context("and input is having less than 2 dots", func() {
			It("should reject the validation", func() {
				result, err := tokenValidator.Validate("aaa.bbb")
				Expect(result).To(BeFalse())
				Expect(err).To(BeIdenticalTo(fjw.ErrMalformedToken))
			})
		})
	})
})
