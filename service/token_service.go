package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type TokenService struct {
	secretKey string
}

type TokenClaims struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func NewTokenService(secretKey string) *TokenService {
	return &TokenService{secretKey: secretKey}
}

// Generate JWT-like token
func (s *TokenService) GenerateToken(userID, username, email string) (string, error) {
	// Create claims
	claims := TokenClaims{
		UserID:    userID,
		Username:  username,
		Email:     email,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(), // Valid for 24 hours
	}

	// Encode claims to JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Base64 encode
	payload := base64.URLEncoding.EncodeToString(claimsJSON)

	// Generate signature
	signature := s.generateSignature(payload)

	// Combine: payload.signature
	token := fmt.Sprintf("%s.%s", payload, signature)

	return token, nil
}

// Validate and parse token
func (s *TokenService) ValidateToken(token string) (*TokenClaims, error) {
	// Split token
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}

	payload := parts[0]
	signature := parts[1]

	// Verify signature
	expectedSignature := s.generateSignature(payload)
	if signature != expectedSignature {
		return nil, errors.New("invalid token signature")
	}

	// Decode payload
	claimsJSON, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("invalid token encoding")
	}

	// Parse claims
	var claims TokenClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, errors.New("invalid token claims")
	}

	// Check expiration
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

func (s *TokenService) generateSignature(payload string) string {
	mac := hmac.New(sha256.New, []byte(s.secretKey))
	mac.Write([]byte(payload))
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}
