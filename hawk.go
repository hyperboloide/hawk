package hawk

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	"github.com/dchest/uniuri"
	"github.com/gin-gonic/gin"
	hawk "github.com/tent/hawk-go"
)

var ErrNotFound = errors.New("Credentials not found")

type Credentials struct {
	Key  string
	User interface{}
}

type CredentialGetFunc func(id string) (*Credentials, error)

type HawkMiddleWare struct {
	GetCredentials      func(id string) (*Credentials, error)
	SetNonce            func(id string, nonce string, t time.Time) (bool, error)
	UserParam           string
	UnauthorizedHandler func(*gin.Context, error)
	ErrorHandler        func(*gin.Context, error)
	Ext                 string
}

func (hm *HawkMiddleWare) BlockRequest(c *gin.Context, err error, auth *hawk.Auth) {
	switch err {
	case hawk.ErrBewitExpired,
		hawk.ErrInvalidBewitMethod,
		hawk.ErrInvalidMAC,
		hawk.ErrMissingServerAuth,
		hawk.ErrNoAuth,
		hawk.ErrReplay,
		hawk.ErrTimestampSkew:
		if auth != nil {
			c.Header("Server-Authorization", auth.ResponseHeader(hm.Ext))
		}
		if hm.UnauthorizedHandler != nil {
			hm.UnauthorizedHandler(c, err)
		} else {
			c.String(http.StatusUnauthorized, err.Error())
		}
	default:
		if hm.ErrorHandler != nil {
			hm.ErrorHandler(c, err)
		} else {
			c.String(
				http.StatusInternalServerError,
				http.StatusText(http.StatusInternalServerError))
		}
	}
}

func (hm *HawkMiddleWare) Filter(c *gin.Context) {
	res := &HawkRequest{
		Hawk: hm,
	}

	auth, err := hawk.NewAuthFromRequest(c.Request, res.CredentialsLookup, res.NonceCheck)
	if res.Error != nil {
		hm.BlockRequest(c, res.Error, nil)
	} else if err != nil {
		hm.BlockRequest(c, err, auth)
	} else if err := auth.Valid(); err != nil {
		hm.BlockRequest(c, err, auth)
	} else {
		c.Header("Server-Authorization", auth.ResponseHeader(hm.Ext))
		c.Set("hawk", auth)
		if hm.UserParam != "" {
			c.Set(hm.UserParam, res.User)
		}
		c.Next()
	}
}

type HawkRequest struct {
	Hawk  *HawkMiddleWare
	ID    string
	User  interface{}
	key   string
	Ok    bool
	Error error
}

func (hr *HawkRequest) CredentialsLookup(creds *hawk.Credentials) error {

	id := creds.ID
	if res, err := hr.Hawk.GetCredentials(id); err != nil {
		hr.Error = err
		return err
	} else if res == nil {
		return ErrNotFound
	} else {
		creds.Key = res.Key
		hr.User = res.User
		creds.Hash = sha256.New
		hr.Ok = true
		return nil
	}
}

func (hr *HawkRequest) NonceCheck(nonce string, t time.Time, creds *hawk.Credentials) bool {
	if hr.Error != nil || !hr.Ok {
		return false
	} else if hr.Hawk.SetNonce == nil {
		return true
	} else if res, err := hr.Hawk.SetNonce(creds.ID, nonce, t); err != nil {
		hr.Error = err
		return false
	} else {
		return res
	}
}

func GenIDKey() (string, string) {
	return uniuri.NewLen(12), uniuri.NewLen(24)
}
