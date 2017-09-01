package firebaseJwtValidator_test

import (
	"net/http"
	"strings"

	"encoding/json"
	fjv "github.com/Morras/firebaseJwtValidator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io/ioutil"
	"log"
)

var _ = Describe("TokenValidator functional test", func() {
	It("Should get a real token and try to validate it using the library", func() {
		token := getFreshToken()

		validator := fjv.NewDefaultTokenValidator("fir-jwtvalidatortest")

		result, err := validator.Validate(token)

		Expect(err).To(BeNil())
		Expect(result).To(BeTrue())
	})
})

func getFreshToken() string {
	reqContent := `{"email":"fjvtestaccount@example.com","password":"Test1234","returnSecureToken":true}`
	req, _ := http.NewRequest("POST", "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=AIzaSyCszb3Vki8T1UmfSFJYTS5qOIffoPNRXb8", strings.NewReader(reqContent))

	req.Header.Add("content-type", "application/json")
	req.Header.Add("referer", "http://fir-jwtvalidatortest.firebaseapp.com/?mode=select")

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)

	if err != nil || resp.StatusCode != 200 {
		Fail("Failed to get token: " + err.Error())
	}

	content, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		Fail("Failed to read body: " + err.Error())
	}

	var body = make(map[string]string)
	err = json.Unmarshal(content, &body)

	token := body["idToken"]

	log.Printf("Retrieved token %v", token)

	return token
}
