package main

import (
	"fmt"
	"log"
	"net/http"
	"simple-token-auth/handler"
	"simple-token-auth/middleware"
	"simple-token-auth/service"
)

func main() {
	// Initialize services
	secretKey := "your-super-secret-key-change-this-in-production"
	tokenService := service.NewTokenService(secretKey)
	authService := service.NewAuthService(tokenService)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService)
	userHandler := handler.NewUserHandler(authService)

	// Public routes (no authentication required)
	http.HandleFunc("/register", authHandler.Register)
	http.HandleFunc("/login", authHandler.Login)

	// Protected routes (authentication required)
	authMiddleware := middleware.AuthMiddleware(tokenService)
	http.Handle("/profile", authMiddleware(http.HandlerFunc(userHandler.GetProfile)))
	http.Handle("/dashboard", authMiddleware(http.HandlerFunc(userHandler.GetDashboard)))

	fmt.Println("🚀 Server running on :8080")
	fmt.Println("\nPublic Endpoints:")
	fmt.Println("  POST /register  - Register new user")
	fmt.Println("  POST /login     - Login and get token")
	fmt.Println("\nProtected Endpoints (require token):")
	fmt.Println("  GET  /profile   - Get user profile")
	fmt.Println("  GET  /dashboard - Get user dashboard")
	fmt.Println("\nNote: You need to install bcrypt first:")
	fmt.Println("  go get golang.org/x/crypto/bcrypt")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
