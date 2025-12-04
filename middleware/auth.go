package middleware

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt"
)

type contextKey string

var userIDKey contextKey = "userID"

func GetUserFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(userIDKey)
	fmt.Println("User ID: ", v)
	
	if v == nil {
		return "", false
	}
	userID, ok := v.(string)
	return userID, ok
}

func Authenticator(next http.Handler) http.Handler {
	secret := []byte(os.Getenv("JWT_SECRET"))
	if len(secret) == 0 {
		panic("JWT_SECRET was not set")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reads cookie to check if the user is logged in or not
		cookie, err := r.Cookie("auth_token")
		if err != nil || cookie.Value == "" {
			http.Error(w, "Unauthorized: Login/Signup First", http.StatusUnauthorized)
			return
		}

		tokenStr := cookie.Value
		// pasring the token in order to verify it
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return secret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized: Login/Signup First", http.StatusUnauthorized)
			return
		}

		claim, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Unauthorized: Login/Signup First", http.StatusUnauthorized)
			return
		}

		sub, ok := claim["sub"].(string)
		if !ok || sub == "" {
			http.Error(w, "Unauthorized: Login/Signup First", http.StatusUnauthorized)
			return
		}

		// attach the user to the context
		ctx := context.WithValue(r.Context(), userIDKey, sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
