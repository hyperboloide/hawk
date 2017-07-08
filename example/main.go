package main

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hyperboloide/hawk"
)

var (
	creds  = map[string]hawk.Credentials{}
	nonces = map[string]bool{}
)

// You will need to provider functions:

// 1. A function that fetch a *hawk.Credentials by it's id.
// if nothing is found the result should be nil and it's
// an authentication error. If an error append (an external
// problem like db connection), return the error and it
// will be set as the context error.
func getCredentials(id string) (*hawk.Credentials, error) {
	res, _ := creds[id]
	return &res, nil
}

// 2. A function that check if a nonce with the same id, value and time
// already exists. If none then returns true and save it so it cannot be
// replayed.
func setNonce(id string, nonce string, t time.Time) (bool, error) {
	key := fmt.Sprintf("%s.%s.%i", id, nonce, t.Unix())
	if _, exists := nonces[key]; exists {
		return false, nil
	}
	nonces[key] = true
	return true, nil
}

func main() {

	// Create a new Middleware with your providers
	middleware := hawk.NewMiddleware(getCredentials, setNonce)

	// Optionally change the user param name in the context.
	// Default is "user" and if empty then the user is not set.
	middleware.UserParam = "hawk-user"

	// set an optional ext param
	middleware.Ext = "my-app"

	router := gin.Default()
	//set middleware
	router.Use(middleware.Filter)
	// a basic view where every request must have an "Authentication" header
	// or if it's a GET request it can have instead a "bewit" parameter.
	router.Any("/:any", func(c *gin.Context) {
		c.String(200, "hello")
	})

	// Create a cred for a user
	id, key := hawk.GenIDKey()
	creds[id] = hawk.Credentials{
		Key: key,
		User: struct {
			Name string
		}{"Fred"},
	}
	router.Run(":8080")
}
