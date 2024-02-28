package jwt

import (
	"fmt"
	"os"
	"strings"

	"github.com/cerberauth/vulnapi/jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

type Algorithm string

const (
	None  Algorithm = "NONE"
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
)

var (
	secret string
	alg    string
	aud    string
)

func GetAlgorithm(alg string) (jwtlib.SigningMethod, error) {
	switch strings.ToUpper(alg) {
	case string(HS256):
		return jwtlib.SigningMethodHS256, nil
	case string(HS384):
		return jwtlib.SigningMethodHS384, nil
	case string(HS512):
		return jwtlib.SigningMethodHS512, nil
	case string(RS256):
		return jwtlib.SigningMethodRS256, nil
	case string(RS384):
		return jwtlib.SigningMethodRS384, nil
	case string(RS512):
		return jwtlib.SigningMethodRS512, nil
	case string(ES256):
		return jwtlib.SigningMethodES256, nil
	case string(ES384):
		return jwtlib.SigningMethodES384, nil
	case string(None):
		return jwtlib.SigningMethodNone, nil
	default:
		return nil, fmt.Errorf("invalid algorithm: %s", alg)
	}
}

func NewRootCmd() (cmd *cobra.Command) {
	rootCmd := &cobra.Command{
		Use:   "jwt",
		Short: "Generate JWT tokens",
	}

	generateCmd := &cobra.Command{
		Use:   "generate [token]",
		Short: "Generate a new JWT token from an existing token",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tokenString := args[0]
			var key interface{}
			var newTokenString string
			tokenWriter, err := jwt.NewJWTWriter(tokenString)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			if secret != "" {
				key = []byte(secret)
			}

			var signingMethod jwtlib.SigningMethod
			if alg != "" {
				if signingMethod, err = GetAlgorithm(alg); err != nil {
					fmt.Println("Error:", err)
					return
				}
			}

			if signingMethod == jwtlib.SigningMethodNone {
				key = jwtlib.UnsafeAllowNoneSignatureType
			}

			if signingMethod == nil || key == nil {
				fmt.Println("Error: algorithm and secret are required")
				return
			}

			newTokenString, err = tokenWriter.SignWithMethodAndKey(signingMethod, key)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			fmt.Println(newTokenString)
		},
	}

	generateCmd.PersistentFlags().StringVarP(&secret, "secret", "", "", "Secret key to sign the token")
	generateCmd.PersistentFlags().StringVarP(&alg, "alg", "", "", "Algorithm to sign the token")
	generateCmd.PersistentFlags().StringVarP(&aud, "aud", "", "", "Audience of the token")

	rootCmd.AddCommand(generateCmd)

	return rootCmd
}

func Execute() {
	c := NewRootCmd()

	if err := c.Execute(); err != nil {
		os.Exit(1)
	}
}
