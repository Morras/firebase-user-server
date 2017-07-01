package firebaseJwtValidator_test

import (
	fjw "github.com/morras/firebaseJwtValidator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("HeaderValidator", func() {

	var projectID = "neutrino-1151"
	var defaultParams = fjw.ValidatorParams{ProjectID: projectID}

	// not json
	var invalidJson = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwIiwgZm9vfQ"
	// invalid base64
	var invalidBase64 = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwIiwgZm9vfQ="
	// old expiration time. Set to 2147483647, should probably get it closer to now for edge case testing
	var expiredInPast = "ew0KICAiaXNzIjogImh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS9uZXV0cmluby0xMTUxIiwNCiAgImF1ZCI6ICJ4eHgtMTE1MSIsDQogICJzdWIiOiAidXNlciBpZCIsDQogICJpYXQiOiAwLA0KICAiZXhwIjogMTQ5ODI0NzM4OA0KfQ"
	// issued at time in the future. Set to 1498247388 (23/06 2017), should probably get it closer to now for edge case testing
	var iatInFuture = "ew0KICAiaXNzIjogImh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS9uZXV0cmluby0xMTUxIiwNCiAgImF1ZCI6ICJ4eHgtMTE1MSIsDQogICJzdWIiOiAidXNlciBpZCIsDQogICJpYXQiOiAyMTQ3NDgzNjQ3LA0KICAiZXhwIjogMjE0NzQ4MzY0Nw0KfQ"
	// invalid audience
	var invalidAudience = "ew0KICAiaXNzIjogImh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS9uZXV0cmluby0xMTUxIiwNCiAgImF1ZCI6ICJ4eHgtMTE1MSIsDQogICJzdWIiOiAidXNlciBpZCIsDQogICJpYXQiOiAwLA0KICAiZXhwIjogMjE0NzQ4MzY0Nw0KfQ"
	// invalid issuer
	var invalidIssuer = "ew0KICAiaXNzIjogImh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS94eHgtMTE1MSIsDQogICJhdWQiOiAibmV1dHJpbm8tMTE1MSIsDQogICJzdWIiOiAidXNlciBpZCIsDQogICJpYXQiOiAwLA0KICAiZXhwIjogMjE0NzQ4MzY0Nw0KfQ"
	// empty subject
	var emptySub = "ew0KICAiaXNzIjogImh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS9uZXV0cmluby0xMTUxIiwNCiAgImF1ZCI6ICJuZXV0cmluby0xMTUxIiwNCiAgInN1YiI6ICIiLA0KICAiaWF0IjogMCwNCiAgImV4cCI6IDIxNDc0ODM2NDcNCn0"
	// valid data issued at time set to 0 and expiration set to 2147483647 so this should not fail untill 2038
	// Audience (and project id) is neutrino-1151
	var validClaims = "ew0KICAiaXNzIjogImh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS9uZXV0cmluby0xMTUxIiwNCiAgImF1ZCI6ICJuZXV0cmluby0xMTUxIiwNCiAgInN1YiI6ICI5U1o5SnZDN0twUEkwUkpHdkFaeE4wc1hUdEgyIiwNCiAgImlhdCI6IDAsDQogICJleHAiOiAyMTQ3NDgzNjQ3DQp9"

	claimsValidator := fjw.ClaimsValidator{}

	Context("Called with a valid string", func() {
		It("should return true", func() {
			result := claimsValidator.Validate(validClaims, defaultParams)
			Expect(result).To(BeTrue())
		})
	})

	Context("Called with invalid json", func() {
		It("should return false", func() {
			result := claimsValidator.Validate(invalidJson, defaultParams)
			Expect(result).To(BeFalse())
		})
	})

	Context("Called with invalid base64", func() {
		It("should return false", func() {
			result := claimsValidator.Validate(invalidBase64, defaultParams)
			Expect(result).To(BeFalse())
		})
	})

	Context("Called with claims with empty subject", func() {
		It("should return false", func() {
			result := claimsValidator.Validate(emptySub, defaultParams)
			Expect(result).To(BeFalse())
		})
	})

	Context("Called with claims that has expired", func() {
		It("should return false", func() {
			result := claimsValidator.Validate(expiredInPast, defaultParams)
			Expect(result).To(BeFalse())
		})
	})

	Context("Called with claims that are issued in the future", func() {
		It("should return false", func() {
			result := claimsValidator.Validate(iatInFuture, defaultParams)
			Expect(result).To(BeFalse())
		})
	})

	Context("Called with claims with wrong audience", func() {
		It("should return false", func() {
			result := claimsValidator.Validate(invalidAudience, defaultParams)
			Expect(result).To(BeFalse())
		})
	})

	Context("Called with claims with wrong issuer", func() {
		It("should return false", func() {
			result := claimsValidator.Validate(invalidIssuer, defaultParams)
			Expect(result).To(BeFalse())
		})
	})
})
