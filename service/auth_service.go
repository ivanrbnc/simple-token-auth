package service

import (
	"errors"
	"fmt"
	"simple-token-auth/domain"

	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	users        map[string]*domain.User // In-memory storage (use DB in production)
	tokenService *TokenService
}

func NewAuthService(tokenService *TokenService) *AuthService {
	return &AuthService{
		users:        make(map[string]*domain.User),
		tokenService: tokenService,
	}
}

func (s *AuthService) Register(req domain.RegisterRequest) (*domain.User, error) {
	// Check if user already exists
	for _, user := range s.users {
		if user.Username == req.Username {
			return nil, errors.New("username already exists")
		}
		if user.Email == req.Email {
			return nil, errors.New("email already exists")
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	userID := fmt.Sprintf("user_%d", len(s.users)+1)
	user := &domain.User{
		ID:       userID,
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
	}

	s.users[userID] = user

	return user, nil
}

func (s *AuthService) Login(req domain.LoginRequest) (*domain.LoginResponse, error) {
	// Find user by username
	var foundUser *domain.User
	for _, user := range s.users {
		if user.Username == req.Username {
			foundUser = user
			break
		}
	}

	if foundUser == nil {
		return nil, errors.New("invalid username or password")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid username or password")
	}

	// Generate token
	token, err := s.tokenService.GenerateToken(foundUser.ID, foundUser.Username, foundUser.Email)
	if err != nil {
		return nil, err
	}

	return &domain.LoginResponse{
		Token: token,
		User:  *foundUser,
	}, nil
}

func (s *AuthService) GetUserByID(userID string) (*domain.User, error) {
	user, exists := s.users[userID]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}
