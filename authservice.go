package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var users = make(map[string]string)
var jwtKey = []byte("my_secret_key")

type Credentials struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/authorize", AuthorizeHandler).Methods("POST")
	r.HandleFunc("/feed", FeedHandler).Methods("GET")

	log.Fatal(http.ListenAndServe(":8000", r))
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := ParseJSONFromRequest(r, &creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, ok := users[creds.Email]; ok {
		http.Error(w, "user already exists", http.StatusBadRequest)
		return
	}

	if !isEmailValid(creds.Email) {
		http.Error(w, "email is not valid", http.StatusBadRequest)
		return
	}

	if !isPasswordStrong(creds.Password) {
		http.Error(w, "weak password", http.StatusBadRequest)
		return
	}

	users[creds.Email] = creds.Password
	w.Write([]byte("registered successfully"))
}

func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := ParseJSONFromRequest(r, &creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[creds.Email]
	if !ok || expectedPassword != creds.Password {
		http.Error(w, "credentials are not valid", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: creds.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		http.Error(w, "could not create access token", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(tokenString))
}

func FeedHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !tkn.Valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Access to feed granted"))
}

func ParseJSONFromRequest(r *http.Request, target interface{}) error {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	return decoder.Decode(target)
}

func isEmailValid(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,15}$`)
	return emailRegex.MatchString(email)
}

func isPasswordStrong(password string) bool {
	var (
		hasMinLen  = len(password) >= 8
		hasUpper   = regexp.MustCompile(`[A-Z]`).MatchString(password)
		hasLower   = regexp.MustCompile(`[a-z]`).MatchString(password)
		hasNumber  = regexp.MustCompile(`[0-9]`).MatchString(password)
		hasSpecial = regexp.MustCompile(`[!@#\$%\^&\*]`).MatchString(password)
	)
	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
}
