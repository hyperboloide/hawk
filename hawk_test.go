package hawk_test

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/dchest/uniuri"
	"github.com/gin-gonic/gin"
	. "github.com/hyperboloide/hawk"
	hawk "github.com/tent/hawk-go"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hawk", func() {

	user := struct {
		ID   int
		Name string
	}{1, "test user"}

	creds := map[string]string{
		"valid-id": "test-cred-key",
	}
	credsError := errors.New("test error")
	getCredentials := func(id string) (*Credentials, error) {
		if id == "error-creds-id" {
			return nil, credsError
		}
		if key, exists := creds[id]; !exists {
			return nil, nil
		} else {
			return &Credentials{
				Key:  key,
				User: user,
			}, nil
		}
	}

	nonces := map[string]bool{}
	setNonces := func(id string, nonce string, t time.Time) (bool, error) {
		if nonce == "error-nonce" {
			return false, credsError
		}
		_, exists := nonces[nonce]
		nonces[nonce] = true
		return !exists, nil
	}

	Context("HawkRequest", func() {
		var hr *HawkRequest
		var hm *HawkMiddleWare

		BeforeEach(func() {
			hm = &HawkMiddleWare{
				GetCredentials: getCredentials,
				SetNonce:       setNonces,
				UserParam:      "user",
				Ext:            "test-hawk",
			}

			hr = &HawkRequest{
				Hawk: hm,
			}
		})

		Describe("CredentialsLookup", func() {
			It("returns error if credentials dont't exist", func() {
				hc := &hawk.Credentials{
					ID: "invalid-id",
				}
				err := hr.CredentialsLookup(hc)
				Expect(err).To(Equal(ErrNotFound))
				Expect(hr.Error).To(BeNil())
				Expect(hr.Ok).To(BeFalse())
				Expect(hr.User).To(BeNil())
			})

			It("returns error of CredentialsLookup func", func() {
				hc := &hawk.Credentials{
					ID: "error-creds-id",
				}
				err := hr.CredentialsLookup(hc)
				Expect(err).To(Equal(credsError))
				Expect(hr.Error).To(Equal(credsError))
				Expect(hr.Ok).To(BeFalse())
				Expect(hr.User).To(BeNil())
			})

			It("returns nil and set HawkRequest if ok", func() {
				hc := &hawk.Credentials{
					ID: "valid-id",
				}
				err := hr.CredentialsLookup(hc)
				Expect(err).ToNot(HaveOccurred())
				Expect(hr.Error).To(BeNil())
				Expect(hc.Key).To(Equal("test-cred-key"))
				Expect(hc.Hash).ToNot(BeNil())
				Expect(hr.User).To(Equal(user))
				Expect(hr.Ok).To(BeTrue())
			})
		})

		Describe("NonceCheck", func() {
			var hc *hawk.Credentials
			t := time.Now()

			BeforeEach(func() {
				hc = &hawk.Credentials{
					ID: "valid-id",
				}
				err := hr.CredentialsLookup(hc)
				Expect(err).ToNot(HaveOccurred())
			})

			It("validate new nonce", func() {
				ok := hr.NonceCheck("my-nonce", t, hc)
				Expect(ok).To(BeTrue())
				Expect(hr.Error).To(BeNil())
			})

			It("don't validate existing nonce", func() {
				ok := hr.NonceCheck("my-nonce", t, hc)
				Expect(ok).To(BeFalse())
				Expect(hr.Error).To(BeNil())
			})

			It("set error", func() {
				ok := hr.NonceCheck("error-nonce", t, hc)
				Expect(ok).To(BeFalse())
				Expect(hr.Error).To(Equal(credsError))
			})

		})

	})

	Context("HawkMiddleWare", func() {
		var ts *httptest.Server
		var hm *HawkMiddleWare
		var credentials *hawk.Credentials

		BeforeEach(func() {
			credentials = &hawk.Credentials{
				ID:   "valid-id",
				Key:  "test-cred-key",
				Hash: sha256.New,
			}

			hm = &HawkMiddleWare{
				GetCredentials: getCredentials,
				SetNonce:       setNonces,
				UserParam:      "user",
			}

			router := gin.New()
			router.Any("/private", hm.Filter, func(c *gin.Context) {
				c.String(200, "ok")
			})
			ts = httptest.NewServer(router)
		})

		AfterEach(func() {
			ts.Close()
		})

		It("valid bwit", func() {
			req, err := http.NewRequest("GET", ts.URL+"/private", nil)
			auth := hawk.NewRequestAuth(req, credentials, time.Hour)
			bw := auth.Bewit()
			resp, err := http.Get(ts.URL + "/private?bewit=" + bw)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
			header := resp.Header["Server-Authorization"][0]
			Expect(auth.ValidResponse(header)).ToNot(HaveOccurred())
		})

		It("expired bwit", func() {
			req, err := http.NewRequest("GET", ts.URL+"/private", nil)
			auth := hawk.NewRequestAuth(req, credentials, -time.Hour)
			bw := auth.Bewit()
			resp, err := http.Get(ts.URL + "/private?bewit=" + bw)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(401))
			header := resp.Header["Server-Authorization"][0]
			Expect(auth.ValidResponse(header)).ToNot(HaveOccurred())
		})

		It("invalid bwit string", func() {
			resp, err := http.Get(ts.URL + "/private?bewit=" + uniuri.NewLen(90))
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(500))
		})

		It("invalid bwit auth key", func() {
			req, err := http.NewRequest("GET", ts.URL+"/private", nil)
			auth := hawk.NewRequestAuth(req, credentials, time.Hour)
			auth.Credentials.Key = "invalid key!"
			bw := auth.Bewit()
			resp, err := http.Get(ts.URL + "/private?bewit=" + bw)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(401))
		})

		It("valid header", func() {
			req, err := http.NewRequest("GET", ts.URL+"/private", nil)
			auth := hawk.NewRequestAuth(req, credentials, 0)
			req.Header.Set("Authorization", auth.RequestHeader())
			client := &http.Client{}
			resp, err := client.Do(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
			header := resp.Header["Server-Authorization"][0]
			Expect(auth.ValidResponse(header)).ToNot(HaveOccurred())

		})

		It("invalid header auth key", func() {
			req, err := http.NewRequest("GET", ts.URL+"/private", nil)
			auth := hawk.NewRequestAuth(req, credentials, 0)
			auth.Credentials.Key = "invalid key!"
			req.Header.Set("Authorization", auth.RequestHeader())
			client := &http.Client{}
			resp, err := client.Do(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(401))
		})

		It("no header no bewit", func() {
			req, err := http.NewRequest("GET", ts.URL+"/private", nil)
			client := &http.Client{}
			resp, err := client.Do(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(401))
		})

	})

	It("GenIDKey", func() {
		id, key := GenIDKey()
		Expect(len(id)).To(Equal(12))
		Expect(len(key)).To(Equal(24))
	})

})