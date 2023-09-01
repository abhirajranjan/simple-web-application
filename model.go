package main

import "github.com/golang-jwt/jwt/v5"

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JwtPayload struct {
	User
	JwtModel
}

type JwtModel struct {
	Iss string           `json:"iss,omitempty"`
	Aud jwt.ClaimStrings `json:"aud,omitempty"`
	Sub string           `json:"sub,omitempty"`
	Azp string           `json:"azp,omitempty"`
	Jti string           `json:"jti,omitempty"`
	Exp *jwt.NumericDate `json:"exp,omitempty"`
	Nbf *jwt.NumericDate `json:"nbf,omitempty"`
	Iat *jwt.NumericDate `json:"iat,omitempty"`
}

func (j JwtModel) GetExpirationTime() (*jwt.NumericDate, error) {
	return j.Exp, nil
}

func (j JwtModel) GetIssuedAt() (*jwt.NumericDate, error) {
	return j.Iat, nil
}

func (j JwtModel) GetNotBefore() (*jwt.NumericDate, error) {
	return j.Nbf, nil
}

func (j JwtModel) GetIssuer() (string, error) {
	return j.Iss, nil
}

func (j JwtModel) GetSubject() (string, error) {
	return j.Sub, nil
}

func (j JwtModel) GetAudience() (jwt.ClaimStrings, error) {
	return j.Aud, nil
}
