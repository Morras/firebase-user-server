package firebaseJwtValidator

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// KeyFetcher interface implementations should get the public key needed to validate a signature based on the keys ID.
type KeyFetcher interface {
	FetchKey(kid string) (*rsa.PublicKey, error)
}

// KeyServerURL points to the location that the CachedKeyFetcher will retrieve its keys from.
const KeyServerURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

// HTTPClient is used to call an URL with a get method and read the response.
type HTTPClient interface {
	Get(string) (*http.Response, error)
}

// CachedKeyFetcher is an implementation of KeyFetcher
type CachedKeyFetcher struct {
	httpClient      HTTPClient
	cache           map[string]string
	cacheExpiration time.Time
}

// NewCachedKeyFetcher creates a new CachedKeyFetcher using httpClient to get data from the key server.
func NewCachedKeyFetcher(httpClient HTTPClient) *CachedKeyFetcher {
	return &CachedKeyFetcher{httpClient: httpClient}
}

// FetchKey returns a PublicKey from its local cache if the cache is not expired.
// If the key does not exist and the cache is not expired, it returns nil and an error.
// The cache expiration is based on the cache-control: max-age as described in the Firebase documentation.
func (kf *CachedKeyFetcher) FetchKey(kid string) (*rsa.PublicKey, error) {
	if time.Now().After(kf.cacheExpiration) {
		err := kf.refreshCache()
		if err != nil {
			return nil, err
		}
	}

	if cert, ok := kf.cache[kid]; ok {
		block, _ := pem.Decode([]byte(cert))
		var cert *x509.Certificate
		cert, _ = x509.ParseCertificate(block.Bytes)
		publicKey := cert.PublicKey.(*rsa.PublicKey)
		return publicKey, nil
	}

	return nil, ErrNoSuchKey
}

func (kf *CachedKeyFetcher) refreshCache() error {
	resp, err := kf.httpClient.Get(KeyServerURL)

	if err != nil || resp.StatusCode != 200 {
		//These should be printed as fatal but without ending the program.
		log.Printf("Unable to connect to google key server, error %v and response %v", err, resp)
		return ErrKeyServerConnectionFailed
	}

	content, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Printf("Unable to read body of response from google key server. %v, %v", err, resp)
		return ErrKeyServerConnectionFailed
	}

	err = json.Unmarshal(content, &kf.cache)

	if err != nil {
		log.Printf("Unable unmarshal body of response from google key server. %v", err)
		return ErrKeyServerConnectionFailed
	}

	kf.updateCacheExpiration(resp)

	return nil
}

func (kf *CachedKeyFetcher) updateCacheExpiration(resp *http.Response) {

	cacheControl := resp.Header.Get("cache-control")

	for _, section := range strings.Split(cacheControl, ",") {
		if strings.Contains(section, "max-age") {
			split := strings.Split(section, "=")
			if len(split) != 2 {
				log.Printf("cache control header does not conform to expected format %v", cacheControl)
				break
			}
			duration, err := time.ParseDuration(strings.Trim(split[1], " ") + "s")
			if err != nil {
				log.Printf("cache control header does not conform to expected format %v", cacheControl)
				break
			}
			kf.cacheExpiration = time.Now().Add(duration)
			break
		}
	}
}
