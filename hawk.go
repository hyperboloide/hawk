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

const (
	AuthKey = "hawk_auth"
	UserKey = "hawk_user"
)

// ErrNotFound is set in context.Err if the GetCredentialFunc
// returns nil
var ErrNotFound = errors.New("Credentials not found")

// Credentials is used to store a key string and a User object.
// It is returned by a function of type GetCredentialFunc.
type Credentials struct {
	Key  string
	User interface{}
}

// GetCredentialFunc is a function that returns a *Credentials by id.
// If nothing is found the result should be nil and it's
// an authentication error (set in context).
// If an error occured (an external problem like db connection),
// return the error and it will be set as the context error.
type GetCredentialFunc func(id string) (*Credentials, error)

// SetNonceFunc is a function that returns false if nonce with the same
// associated id and time already exists. Otherwise true is returned
// an the nonce should be save to avoid replay problems.
type SetNonceFunc func(id string, nonce string, t time.Time) (bool, error)

type AbortHandlerFunc func(*gin.Context, error)

// Middleware is the middleware object.
// GetCredentials is the GetCredentialFunc
// SetNonce is the SetNonceFunc
// UserParam if set will set the user in the context with a matching key
// Ext add an "ext" header in the request
type Middleware struct {
	GetCredentials GetCredentialFunc
	SetNonce       SetNonceFunc
	AbortHandler   AbortHandlerFunc
	UserParam      string
	Ext            string
}

// NewMiddleware creates a new Middleware with the GetCredentials
// and SetNonce params set. UserParam is set to "user" by default.
func NewMiddleware(gcf GetCredentialFunc, snf SetNonceFunc) *Middleware {
	return &Middleware{
		GetCredentials: gcf,
		SetNonce:       snf,
	}
}

func ISHawkError(err error) bool {
	switch err {
	case ErrNotFound,
		hawk.ErrBewitExpired,
		hawk.ErrInvalidBewitMethod,
		hawk.ErrInvalidMAC,
		hawk.ErrMissingServerAuth,
		hawk.ErrNoAuth,
		hawk.ErrReplay,
		hawk.ErrTimestampSkew:
		return true
	}
	return false
}

// Abortequest aborts the request and set the context error and status.
// When possible it will attempt to send a "Server-Authorization" header.
func (hm *Middleware) Abortequest(c *gin.Context, err error, auth *hawk.Auth) {
	isHawk := ISHawkError(err)
	if isHawk && auth != nil {
		c.Header("Server-Authorization", auth.ResponseHeader(hm.Ext))
	}
	if hm.AbortHandler != nil {
		hm.AbortHandler(c, err)
		c.Abort()
	} else if isHawk {
		c.AbortWithError(http.StatusUnauthorized, err)
	} else {
		c.AbortWithError(http.StatusInternalServerError, err)
	}
}

// Filter is the middleware function that validate the hawk authentication.
func (hm *Middleware) Filter(c *gin.Context) {
	res := &Request{
		Hawk: hm,
	}

	auth, err := hawk.NewAuthFromRequest(c.Request, res.CredentialsLookup, res.NonceCheck)
	if res.Error != nil {
		hm.Abortequest(c, res.Error, nil)
	} else if err != nil {
		hm.Abortequest(c, err, auth)
	} else if err := auth.Valid(); err != nil {
		hm.Abortequest(c, err, auth)
	} else {
		c.Header("Server-Authorization", auth.ResponseHeader(hm.Ext))
		c.Set(AuthKey, auth)
		c.Set(UserKey, res.User)
		c.Next()
	}
}

// Request represent the state of a request.
type Request struct {
	Hawk  *Middleware
	ID    string
	User  interface{}
	Ok    bool
	Error error
}

// CredentialsLookup lookup the credantial for hawk-go from the user
// provided GetCredentialFunc.
func (hr *Request) CredentialsLookup(creds *hawk.Credentials) error {

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

// NonceCheck call the SetNonceFunc on behalf of hawk-go.
func (hr *Request) NonceCheck(nonce string, t time.Time, creds *hawk.Credentials) bool {
	if hr.Error != nil || !hr.Ok || hr.Hawk.SetNonce == nil {
		return false
	}

	ok, err := hr.Hawk.SetNonce(creds.ID, nonce, t)
	if err != nil {
		hr.Error = err
		return false
	}
	return ok
}

// GenIDKey generates a random id and key.
func GenIDKey() (string, string) {
	return uniuri.NewLen(12), uniuri.NewLen(24)
}
