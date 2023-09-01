package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtStandards JwtModel
	jwtMethod    jwt.SigningMethod
	jwtKeyFunc   jwt.Keyfunc
)

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/username", authMiddleware(http.HandlerFunc(usernameHandler)))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var (
		user       User
		jwtpayload JwtPayload
	)

	buffer := io.LimitReader(r.Body, 10000)
	if err := json.NewDecoder(buffer).Decode(&user); err != nil {
		slog.Info("failed decoding bytes", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	jwtpayload = JwtPayload{
		User:     user,
		JwtModel: jwtStandards,
	}

	token := jwt.NewWithClaims(jwtMethod, &jwtpayload)
	key, err := jwtKeyFunc(token)
	if err != nil {
		slog.Info("error getting key", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	signedtoken, err := token.SignedString(key)
	if err != nil {
		slog.Error("failed to create token", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "%s", signedtoken)
}

func authMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
		if len(authHeader) != 2 {
			slog.Info("Malformed token")
			http.Error(w, "Malformed Token", http.StatusUnauthorized)
			return
		}

		requestToken := authHeader[1]
		token, err := jwt.Parse(requestToken, jwtKeyFunc)
		if err != nil {
			slog.Error("error parsing token", err)
			http.Error(w, "Malformed Token", http.StatusBadRequest)
			return
		}

		payload, ok := token.Claims.(JwtPayload)
		if !ok {
			slog.Error("error typecasting token claims to payload", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), "username", payload.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func usernameHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		slog.Error("error getting username")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(username))
}
