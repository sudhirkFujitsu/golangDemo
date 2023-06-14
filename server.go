package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var (
	// Define your self-made RS256 key
	rsaPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
<YOUR RSA PRIVATE KEY>
-----END RSA PRIVATE KEY-----
`

	// Create a global signing key instance
	signingKey *rsa.PrivateKey

	// Define the client credentials
	clientID     = "your-client-id"
	clientSecret = "your-client-secret"
)

func init() {
	// Parse the RSA private key
	block, _ := pem.Decode([]byte(rsaPrivateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal("Failed to decode PEM block containing RSA private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Failed to parse RSA private key: ", err)
	}
	signingKey = key
}

func main() {
	r := mux.NewRouter()

	// Define the /token endpoint for issuing access tokens
	r.HandleFunc("/token", TokenHandler).Methods("POST")

	// Define the /keys endpoint for listing the signing keys
	// r.HandleFunc("/keys", KeysHandler).Methods("GET")

	// Define the /introspect endpoint for token introspection
	r.HandleFunc("/introspect", IntrospectHandler).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", r))
}

// TokenHandler generates and returns a JWT access token
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	// Validate basic authentication
	user, pass, _ := r.BasicAuth()
	if user != clientID || pass != clientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Create the claims for the JWT token
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	// Generate the access token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return the access token
	response := map[string]string{
		"access_token": signedToken,
		"token_type":   "Bearer",
		"expires_in":   "3600",
	}
	jsonResponse, _ := json.Marshal(response)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

// // KeysHandler lists the signing keys
// func KeysHandler(w http.ResponseWriter, r *http.Request) {
// 	// Get the public key from the signing key
// 	publicKey := signingKey.PublicKey
// 	rsaPublicKey := publicKey.(*rsa.PublicKey)

// 	// Encode the public key to PEM format
// 	publicKeyBytes, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
// 	if err != nil {
// 		w.WriteHeader(http.StatusInternalServerError)
// 		return
// 	}
// 	pemEncodedKey := pem.EncodeToMemory(&pem.Block{
// 		Type:  "PUBLIC KEY",
// 		Bytes: publicKeyBytes,
// 	})

// 	// Return the public key
// 	w.Header().Set("Content-Type", "application/x-pem-file")
// 	w.WriteHeader(http.StatusOK)
// 	w.Write(pemEncodedKey)
// }

// IntrospectHandler checks the validity of a token
func IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the token from the request body
	tokenString := r.FormValue("token")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return signingKey.Public(), nil
	})
	if err != nil || !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Return token details
	response := map[string]interface{}{
		"active": true,
	}
	jsonResponse, _ := json.Marshal(response)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}
