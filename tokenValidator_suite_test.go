package firebaseJwtValidator_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestFirebaseTokenValidator(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Firebase token validator Suite")
}
