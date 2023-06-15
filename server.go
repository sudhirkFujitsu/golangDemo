package main

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var users = map[string]string{
	"sudhier": "password",
	"sudhier1": "password1",
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var keyFiles = map[string]string{
	"public":  "keys/jwtRSA256-public.pem",
	"private": "keys/jwtRSA256-private.pem",
}

type IntrospectiveResponse struct {
	Active     bool    `json:"active"`
	Username   string  `json:"username"`
	Type       string  `json:"token_type"`
	Expiration float64 `json:"exp"`
}

type TokenData struct {
	TokenString string `json:"token"`
}

func Token(username string) (string, time.Time, error) {
	return TokenWithExpiration(username, 5*time.Minute)
}

func TokenWithExpiration(username string, expiration time.Duration) (string, time.Time, error) {
	prvKey, readErr := os.ReadFile(keyFiles["private"])
	if readErr != nil {
		return "", time.Now(), readErr
	}

	jwtKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(prvKey))
	if err != nil {
		return "", time.Now(), err
	}

	expirationTime := time.Now().Add(expiration)

	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)

	return tokenString, expirationTime, err

}

func SignIn(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if ok {
		expectedPassword, okUser := users[username]

		if !okUser || expectedPassword != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	} else {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString, expirationTime, err := Token(username)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	w.Write([]byte(fmt.Sprintf("Your current token is: %s", tokenString)))
}

func TokenCheck(r *http.Request) (int, *Claims) {
	claims := &Claims{}

	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			return http.StatusUnauthorized, claims
		}
		return http.StatusBadRequest, claims
	}

	tknStr := c.Value

	pubKey, _ := os.ReadFile(keyFiles["public"])
	jwtKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKey))

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid || strings.HasPrefix(err.Error(), jwt.ErrTokenExpired.Error()) {
			return http.StatusUnauthorized, claims
		}
		return http.StatusBadRequest, claims
	}
	if !tkn.Valid {
		return http.StatusUnauthorized, claims
	}

	return http.StatusOK, claims
}

func Welcome(w http.ResponseWriter, r *http.Request) {
	httpStatus, claims := TokenCheck(r)
	if httpStatus != http.StatusOK {
		w.WriteHeader(httpStatus)
		if httpStatus == http.StatusUnauthorized {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		if httpStatus == http.StatusBadRequest {
			http.Error(w, "BasRequest", http.StatusBadRequest)
		}
		return
	}

	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

func Introspection(w http.ResponseWriter, r *http.Request) {
	httpStatus, _ := TokenCheck(r)
	if httpStatus != http.StatusOK {
		w.WriteHeader(httpStatus)
		if httpStatus == http.StatusUnauthorized {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		if httpStatus == http.StatusBadRequest {
			http.Error(w, "BasRequest", http.StatusBadRequest)
		}
		return
	}

	var token TokenData
	err := json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	pubKey, _ := os.ReadFile(keyFiles["public"])
	jwtKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKey))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Ready key failed")))
		return
	}

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(token.TokenString, claims, func(parsedToken *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Token Inspection failed!")))
		return
	}

	var introResp = IntrospectiveResponse{
		Active:     parsedToken.Valid,
		Username:   claims["username"].(string),
		Type:       parsedToken.Header["typ"].(string),
		Expiration: claims["exp"].(float64),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(introResp)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
	w.Write([]byte(fmt.Sprintf("You are now loged out!")))
}

func HelloWorld(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(fmt.Sprintf("Hello sudhier!")))
}

func main() {
	http.HandleFunc("/", HelloWorld)
	http.HandleFunc("/welcome", Welcome)
	http.HandleFunc("/token", SignIn)
	http.HandleFunc("/inspect", Introspection)
	http.HandleFunc("/logout", Logout)

	log.Fatal(http.ListenAndServe(":8080", nil))
}