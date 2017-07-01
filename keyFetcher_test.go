package firebaseJwtValidator_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"bytes"
	"io/ioutil"
	"net/http"

	"log"

	fjw "github.com/morras/firebaseJwtValidator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"time"
)

type HttpMock struct {
	Url         string
	CalledCount int
	Response    *http.Response
}

func (h *HttpMock) Get(url string) (*http.Response, error) {
	log.Printf("Get called count was %v", h.CalledCount)
	h.Url = url
	h.CalledCount += 1
	log.Printf("Get called count is now %v", h.CalledCount)
	return h.Response, nil
}

var _ = Describe("GoogleKeyFetcher", func() {
	// Response is taking from googles server on June 30th 2017 for accuracy
	responseContent := `{
 "5800065c68da963a267e0b9c50310766c91b84f5": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIF05znJvEvAIwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcw\nNjMwMDA0NTI2WhcNMTcwNzAzMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAIv1ZPf1eUj8dAPImfphm7+w2yXdBdbAi0bPh+gosPz1rGhf\ncJ/lM7r/Gt9HGrz9NWMvhM+DmS8OJlce0cTYl57a0JN5DrdN9eKsLYsm82rwbxK4\nkoLhfNJTxIrh0dUsBTJeE4reVISjQyA/5+MmW37n3LvQkLpeu4jllHXJdf5mkrLE\nTDEwrutBZDDVm9JV+TsHck6An7JxAKJGROtVka1wlU8xyVCMk7GQLGd9b4hGqxto\naeufg+nRceCsDnnSFCY3B2xtjsz3bRrAbvrH2CIX+h+N5Ipk2staHshEg2mfB7Rs\ni5l7L65f9sy9/YgB0EYsy4imdh9DJK2rduqxAY8CAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAAG/tUvCvEdNOlvlttcjzrWS1qj1RiGInCCuFAbnZg2V\np2izTwlI2YSB33fnwJs2uy6TTgM6GoiAGItWE4byO3b4vOUEBNjpzS+gYzhy39tR\nPTI4czWuPyyIQjntMb0So5bcCxLViHodAwG3ARINx1bS5LwPmyLvo6DpLmtGi4o0\nqVBNZzhNMc3vd0+NJ20sc0h5+QcjnnWFQGyjwgyYfEU0zFHnlIaJcMI/YGNGM+4r\nOBW37PRp0Qi+PCn4xKDdXGV/yg0PW1qSMu2LBlXdDZvmFL7J0ZnO1GR2pJWyMaJR\nIf+IJcWaK0A9j41GS2qeUFUhQKuuA9HgmRMaF5EPoXU=\n-----END CERTIFICATE-----\n",
 "8a22e940fa0b0050a7a910c94d3f36ee4c69a2e4": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIMHMF2XIvsTYwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcw\nNjI4MDA0NTI2WhcNMTcwNzAxMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAK3iQEzBq7quT/7g7kLNdu0EhFTxdELMq6n2Te1n5wGNtv5q\nelAxoe9WcZ5jBJe6KxfFD3TD7L4goAsNgdlGHOFACUarrBaUCKwb6f2Q26XHuVws\nMe5wBvwpfHQ3G4t12hO6k6IRbWG83cZaReQdOA+nN/F252QAABuw4pECFJasZa9y\nGzjG+37V2SZgBKToqeN5GYNgsbZsJTKYuLwsDSQUIW0IcOiugQy1wTQYU+Urnoz2\n3ABZF4U8tYyeI7W1ZOr+oU/BcjzOkGpbkApse1Ei5Ieyvm+Tz4pi6wmSja5qcKkL\nZc2Yt4ObzvaC2vza78J08yBd3cF/UAYLOxEVQS8CAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAEGe158vjJuMA6paKQo2v0Mxl+UMYFUfK4N2Fz0KhtFF\naKwILAFwpb2DYI6AhgtlCx/JsESivw49aeRignURi4TQAFzBdEVl9onCPJHWejZI\nOp1kSqZNjU2DA930bzA7HpkLQ+d5nvO5txQXxTNWww88a5oViwmHbRmnOGdEnb9x\nMGa65fY0SW7kPy5slJoh3WAtRDezWO23ZAodF5yR1esCtSADxknnOBns9wxGsjS9\nGlICEi9kRJjgHppNo+lWRP1tYcLiRzfmUr/IH3eJjNvSVgbmf4tk5Y0q/CSNIYdT\nC5+8lD4KRRXPzE5/XU2yOK/0DFL+SW3QXF0g9rsvBd0=\n-----END CERTIFICATE-----\n",
 "42e2d53fcbeb352af4f90292291e6188af0a1f0e": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIJBuFiMWJ0uMwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcw\nNjI5MDA0NTI2WhcNMTcwNzAyMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAN1Z5dpGnx2UFGbr1luMdO2WO/Av3U7B6/YJ8kZ91LA0NI5g\n5XmKDRB1590C55PyZaFULBE5ItTR8WkD27ZMKK3ZZbt2hbKgKU7K/EQN2FCMCf/C\nXy0B/c/04NXLYtSXKw1ukh9W5zZC2eO3+9yy/tBeAvKFAytL/VTLumaUAeNYvYzA\n4mU0+BgvU/RuMiT4IjcJWhvOR15pHrPMHURxLMJFel0PYIiyX1IYokfbrunnN0cT\ngOm3VUYekWUC8iDDGfLEL0Z/sjxXQe0DSCj7NJmLK+7BNDVGzWTPbcHQeiB1qWs+\nUDhLGvebkcpuzDWORuZIMmPibmeOAI0CHQf/QD8CAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAAe8KakZ1nQwc4p8qtHM495TFbrG5pNbX+tzbCijm912\n/tLTvPTuIiCTwbIgOTnse8zidEzLt1pFzEU3P92j1usTAk+byOIPmJ3TGRr9aS+3\nx534CootmNqOQB0Oi4iNFqcEXvKAA834SpDsKf55ZBKCKPW3VyMvh9Z4lYlmy7SU\nzMPCix6Lo8VBPozeZt2jhqqxIuoGebNte2yOhJ0dylxMdCyCtUIhMIpeIpODmrkx\n1/ir4hy4NNyOMARDqV39VzCqCNlzkHm72Ag0nsqcuyWuekJEGzOHFz8Z74MlnPbX\nzmaKSR3fhBjWZ+jh8/CEXXbJ4NMbjamrprd6tbtb4qM=\n-----END CERTIFICATE-----\n",
 "6d2c28ba7db93388e12af78d34f75c8888ec52ca": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIN6sNh8+oJ+gwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcw\nNzAxMDA0NTI2WhcNMTcwNzA0MDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBANY1CriN231UELD1jj+TKWmtnW2sxeMoXlxrSENRtiBbdwgv\n9g11C7sSqRm5E57cDhW9lfCgFCdWZMApDcHhlDrl6LUaPeUlr73myou/5tPNl77C\n6wyfpzJD7FBv/uxzGynvZFxSg+zaPK4kIi0b3vriDUH1QEk211W+AU1w2YXXd9K6\n+x1TJpIhrH1M5n069f5BxyLWwG95yfr9nlltMktLYWuq4Niw+yASS4kAImNMQhaH\nCG1jDo1iQmXvwyZThCSUnV6kmXaaiURfIIJ/PhuSjMoHQ2rCW0+LRXHV0w7Zq1lN\nl4wHCcpF2O79WBfmZkYDMI+V/SUYGbbzKFQaBRMCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAJoVOhSkarngMVTicnAv2Cexm84iCkLQD7GND8VviTka\np4TsjtCpHEXZe/wk9Fo6lMc+T+am6Y5/ZOq/4SN5UiayTnz3H7fvJ62hNu2Qco/V\nO1pb48b6/NKwWBcqXYfEOZNLN/NmHL9arR1s1Hm0vnEP6CAyTkHyCa37ksbSyNy5\nZ8ePQo2vA1eLPCL/ezrLCXcSkgU0Pypcbl3J+Yz8s17LcRF5doA3hdpTXw+L6m7v\nJzMg8uERJoPfiKAE447u4MNOcjtCSS5skmw1qVlB9CQOrbUqb6IEgDHLNZdvWSLe\nRApATKRJHRC0eIYLtL2i5mRQmUmzN3Ex3nNshCU6kjo=\n-----END CERTIFICATE-----\n"
}`

	existingKid := "8a22e940fa0b0050a7a910c94d3f36ee4c69a2e4"
	nonExistingKid := "DummyKid"

	block, _ := pem.Decode([]byte("-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIMHMF2XIvsTYwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcw\nNjI4MDA0NTI2WhcNMTcwNzAxMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAK3iQEzBq7quT/7g7kLNdu0EhFTxdELMq6n2Te1n5wGNtv5q\nelAxoe9WcZ5jBJe6KxfFD3TD7L4goAsNgdlGHOFACUarrBaUCKwb6f2Q26XHuVws\nMe5wBvwpfHQ3G4t12hO6k6IRbWG83cZaReQdOA+nN/F252QAABuw4pECFJasZa9y\nGzjG+37V2SZgBKToqeN5GYNgsbZsJTKYuLwsDSQUIW0IcOiugQy1wTQYU+Urnoz2\n3ABZF4U8tYyeI7W1ZOr+oU/BcjzOkGpbkApse1Ei5Ieyvm+Tz4pi6wmSja5qcKkL\nZc2Yt4ObzvaC2vza78J08yBd3cF/UAYLOxEVQS8CAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAEGe158vjJuMA6paKQo2v0Mxl+UMYFUfK4N2Fz0KhtFF\naKwILAFwpb2DYI6AhgtlCx/JsESivw49aeRignURi4TQAFzBdEVl9onCPJHWejZI\nOp1kSqZNjU2DA930bzA7HpkLQ+d5nvO5txQXxTNWww88a5oViwmHbRmnOGdEnb9x\nMGa65fY0SW7kPy5slJoh3WAtRDezWO23ZAodF5yR1esCtSADxknnOBns9wxGsjS9\nGlICEi9kRJjgHppNo+lWRP1tYcLiRzfmUr/IH3eJjNvSVgbmf4tk5Y0q/CSNIYdT\nC5+8lD4KRRXPzE5/XU2yOK/0DFL+SW3QXF0g9rsvBd0=\n-----END CERTIFICATE-----\n"))
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	expectedPublicKey := cert.PublicKey.(*rsa.PublicKey)

	var keyFetcher fjw.KeyFetcher
	var mock *HttpMock
	var mockResponse *http.Response

	BeforeEach(func() {
		mockResponse = &http.Response{Body: ioutil.NopCloser(bytes.NewBuffer([]byte(responseContent)))}
		mockResponse.Header = http.Header{}
		mock = &HttpMock{Response: mockResponse}
		keyFetcher = fjw.NewGoogleKeyFetcher(mock)
	})

	Context("When no cache exists", func() {
		Context("And there is no cache", func() {
			It("Should call the key server", func() {
				mockResponse.StatusCode = 200
				mockResponse.Header.Add("cache-control", "public, max-age=3, must-revalidate, no-transform")

				keyFetcher.FetchKey(existingKid)

				Expect(mock.CalledCount).To(BeIdenticalTo(1))
				Expect(mock.Url).To(BeIdenticalTo(fjw.KeyServerURL))
			})
		})

		Context("And the key exists in the key list received from the server", func() {
			It("Should return the corresponding key", func() {
				mockResponse.StatusCode = 200
				mockResponse.Header.Add("cache-control", "public, max-age=3, must-revalidate, no-transform")

				result, err := keyFetcher.FetchKey(existingKid)
				Expect(err).To(BeNil())
				Expect(result).To(Equal(expectedPublicKey))
			})
		})

		Context("And the key does not exists in the key list received from the server", func() {
			It("Should return an error", func() {
				mockResponse.StatusCode = 200
				mockResponse.Header.Add("cache-control", "public, max-age=3, must-revalidate, no-transform")

				_, err := keyFetcher.FetchKey(nonExistingKid)
				Expect(err).To(BeIdenticalTo(fjw.ErrNoSuchKey))
			})
		})

		Context("And there is an error connecting to the server", func() {
			It("Should return an error", func() {
				mockResponse.StatusCode = 500
				mockResponse.Header.Add("cache-control", "public, max-age=3, must-revalidate, no-transform")

				result, err := keyFetcher.FetchKey(existingKid)
				Expect(result).To(BeNil())
				Expect(err).To(BeIdenticalTo(fjw.ErrKeyServerConnectionFailed))
			})
		})

		Context("And the servers response does not expire before the next call", func() {
			It("Should only call the server once", func() {
				mockResponse.StatusCode = 200
				mockResponse.Header.Add("cache-control", "public, max-age=3, must-revalidate, no-transform")

				keyFetcher.FetchKey(existingKid)
				keyFetcher.FetchKey(existingKid)

				Expect(mock.CalledCount).To(BeIdenticalTo(1))
			})
		})

		Context("And the servers response expires before the next call", func() {
			It("Should call the server again", func() {
				mockResponse.StatusCode = 200
				mockResponse.Header.Add("cache-control", "public, max-age=2, must-revalidate, no-transform")

				keyFetcher.FetchKey(existingKid)
				sleepSeconds := 3
				time.Sleep(time.Duration(sleepSeconds) * time.Second)
				keyFetcher.FetchKey(existingKid)

				Expect(mock.CalledCount).To(BeIdenticalTo(2))
			})
		})
	})
})

var _ = Describe("Integration test of GoogleKeyFetcher", func() {
	keyFetcher := fjw.NewGoogleKeyFetcher(&http.Client{})

	It("Should return with key not found error but no server error", func() {
		_, err := keyFetcher.FetchKey("InvalidKeyID")
		Expect(err).To(BeIdenticalTo(fjw.ErrNoSuchKey))
	})
})
