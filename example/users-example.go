package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	api "github.com/carsonfeng/appstoreconnect-openapi-go/generated"

	"github.com/dgrijalva/jwt-go"
)

// Variables from the appstore
// from https://developer.apple.com/documentation/appstoreconnectapi/generating_tokens_for_api_requests
var authKeyP8 = "<P8 Key String>"
var iss = "<Issuer ID>"
var kid = "<Key identifier>"

func main() {
	expireTime := time.Now().Add(time.Minute * 10).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": iss,
		"exp": expireTime,
		"aud": "appstoreconnect-v1",
	})
	token.Header["kid"] = kid

	key, err := getPrivateKey(authKeyP8)
	if err != nil {
		fmt.Println(err)
		return
	}
	signedToken, err := token.SignedString(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	cfg := api.NewConfiguration()
	// cfg.Debug = false
	auth := context.WithValue(context.Background(), api.ContextAccessToken, signedToken)
	client := api.NewAPIClient(cfg)

	response, _, e := client.UsersApi.UsersGetCollection(auth).Execute()

	if e != nil {
		fmt.Println(e)
		return
	}
	for _, user := range response.Data {
		fmt.Println(user.Attributes.Username)
	}
}

// Reads a p8 file and returns the ecdsa private key
func getPrivateKey(authKeyP8 string) (*ecdsa.PrivateKey, error) {
	var err error
	fileData := []byte(authKeyP8)
	var parsedKey interface{}
	var key *ecdsa.PrivateKey
	var ok bool
	block, _ := pem.Decode(fileData)
	if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil, err
	}
	if key, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, fmt.Errorf("Not a EC private key file")
	}
	return key, nil
}
