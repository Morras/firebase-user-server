package firebaseJwtValidator_test

import (
	fjv "github.com/morras/firebaseJwtValidator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DefaultHeaderValidator", func() {

	// alg = RS256 kid = 10
	var validHeader = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwIn0"
	// alg = RSxxx kid = 10
	var invalidAlgorithm = "eyJhbGciOiJSU3h4eCIsImtpZCI6IjEwIn0"
	// alg = RS256 no kid
	var noKid = "eyJhbGciOiJSUzI1NiJ9"
	// not json
	var invalidJson = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwIiwgZm9vfQ"
	// invalid base64
	var invalidBase64 = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwIiwgZm9vfQ="

	headerValidator := fjv.DefaultHeaderValidator{}

	Context("Called with a valid string", func() {
		It("should return true", func() {
			result := headerValidator.Validate(validHeader)
			Expect(result).To(BeTrue())
		})
	})

	Context("Called with string not in base64", func() {
		It("should return false", func() {
			result := headerValidator.Validate(invalidBase64)
			Expect(result).To(BeFalse())
		})
	})

	Context("Called with string missing kid", func() {
		It("should return false", func() {
			result := headerValidator.Validate(noKid)
			Expect(result).To(BeFalse())
		})
	})

	Context("Called with string with invalid algorithm", func() {
		It("should return false", func() {
			result := headerValidator.Validate(invalidAlgorithm)
			Expect(result).To(BeFalse())
		})
	})

	Context("Called with string not containing valid json", func() {
		It("should return false", func() {
			result := headerValidator.Validate(invalidJson)
			Expect(result).To(BeFalse())
		})
	})
})
