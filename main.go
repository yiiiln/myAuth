package myAuth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"net/http"
	"strings"
)

type authHeader struct {
	BearerToken string `header:"Authorization"`
}

func AuthJWT() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		header := authHeader{}

		if err := ctx.ShouldBindHeader(&header); err != nil {
			parametersError := errors.New(" Invalid request parameters.")
			ctx.JSON(http.StatusBadRequest, gin.H{
				"status": gin.H{
					"code":    http.StatusBadRequest,
					"error: ": parametersError.Error(),
				},
			})
			ctx.AbortWithError(http.StatusBadRequest, parametersError)
			return
		}

		idTokenHeader := strings.Split(header.BearerToken, "Bearer ")

		if len(idTokenHeader) < 2 {
			lenError := errors.New(" Must provide Authorization header with format `Bearer {token}`")
			ctx.JSON(http.StatusBadRequest, gin.H{
				"status": gin.H{
					"code":    http.StatusBadRequest,
					"error: ": lenError.Error(),
				},
			})
			ctx.AbortWithError(http.StatusBadRequest, lenError)
			return
		}

		// validate ID token here
		jwToken := strings.Split(header.BearerToken, "Bearer ")[1]
		token, err := verifyToken(jwToken)
		if err != nil {
			//ctx.AbortWithError(http.StatusBadRequest, err)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctx.Set("decode_az_jwt", token.Claims)
		ctx.Next()
	}
}

func verifyToken(tokenString string) (*jwt.Token, error) {
	keySet, err := jwk.Fetch(context.Background(), "https://login.microsoftonline.com/common/discovery/v2.0/keys")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwa.RS256.String() {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		keys, ok := keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key %v not found", kid)
		}

		jwtPublicKey := &rsa.PublicKey{}
		err = keys.Raw(jwtPublicKey)
		if err != nil {
			return nil, fmt.Errorf("could not parse pubkey")
		}
		return jwtPublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

