package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	// "os"

	"github.com/Omsh24/pokedexSLice/database"
	"github.com/Omsh24/pokedexSLice/middleware"
	"github.com/Omsh24/pokedexSLice/models"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}
	secrets := os.Getenv("JWT_SECRET")
	if secrets == "" {
		log.Fatal("PROBLEM GETTING JWT_SECRET")
	}
	jwtSecret = []byte(secrets)
}

// PUBLIC ROUTES

// Signup functionalities
func createUser(ctx context.Context, name string, email string, password string) (*models.User, error) {
	// user validation checks
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	if name == "" || email == "" || password == "" {
		return nil, fmt.Errorf("missing required fields")
	}
	if len(password) < 4 {
		return nil, fmt.Errorf("password length is too small")
	}

	// checking if user already exixts
	count, err := database.UserCollection.CountDocuments(ctx, bson.M{
		"email": email,
	})
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("user already exists")
	}

	// hashing the password using bcrypt
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashed := string(bytes)
	if err != nil {
		return nil, err
	}

	user := models.User{
		ID:           primitive.NewObjectID(),
		Name:         name,
		Email:        email,
		PasswordHash: hashed,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	_, err = database.UserCollection.InsertOne(ctx, user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// this function creates a user token that will allow the user to staty logged in for the next 24 hours
func generateJWT(userId primitive.ObjectID, email string) (string, error) {
	// this is where we give in the data that we want to embed inside the token
	claims := jwt.MapClaims{
		"sub":   userId.Hex(), // who is this token about? Hex will conv userid into a string
		"email": email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"iat":   time.Now().Unix(), // issued at
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func Signup(w http.ResponseWriter, r *http.Request) {
	// this means everything I will send will be of type json
	w.Header().Set("Content-Type", "application/json")

	// this object helps us decode how the request body structure for signup should look like
	var signupTemplate models.SignupTemplate
	if err := json.NewDecoder(r.Body).Decode(&signupTemplate); err != nil {
		http.Error(w, "Invalid body request", http.StatusBadRequest)
		return
	}

	// in case decoding this request will take more than 5 sec time it will be cancelled
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// we are sending all the data necessory to create a user
	user, err := createUser(ctx, signupTemplate.Name, signupTemplate.Email, signupTemplate.Password)
	if err != nil {
		if err.Error() == "user already exists" {
			http.Error(w, "email already in use", http.StatusConflict)
			return
		}
		log.Println("createUser error: ", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	token, err := generateJWT(user.ID, user.Email)
	if err != nil {
		log.Println("generateJWT error: ", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// sets up a session for user of 24 hours
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	// making a json to show that the user signup was successful
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":    user.ID.Hex(),
		"name":  user.Name,
		"email": user.Email,
		"token": token,
	})
}

// LOGIN FUNCTIONALITIES

func findUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := database.UserCollection.FindOne(ctx, bson.M{
		"email": email,
	}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var loginTemplate models.LoginTemplate
	if err := json.NewDecoder(r.Body).Decode(&loginTemplate); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// checking if the user exsists in the database
	user, err := findUserByEmail(ctx, loginTemplate.Email)
	if err != nil {
		http.Error(w, "no such user found", http.StatusBadRequest)
		return
	}

	// comparing the user's entered password to the hashed password stored in db
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(loginTemplate.Password)); err != nil {
		http.Error(w, "password did not match", http.StatusBadRequest)
		return
	}

	// again setting up a session for the user
	token, err := generateJWT(user.ID, user.Email)
	if err != nil {
		log.Println("generateJWT err:", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "login successful",
		"token":   token,
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "", // changed from token in "" -> to remove the token
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0), // kills immediately
		MaxAge:   -1,
	})

	json.NewEncoder(w).Encode(map[string]string{
		"message": "logged out",
	})
}

// PRIVATE ROUTE
func Home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userID, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized: Login/Signup First", http.StatusUnauthorized)
		return
	}

	// converting the user ID from string (hex) to primitive.ObjectID
	hexUserID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Cann't find the user", http.StatusUnauthorized)
		return
	}
	// fmt.Println(hexUserID)

	// providing context
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// creating a user instance
	var user models.User
	// finding the user in the database based on bson attribute given (_id)
	err = database.UserCollection.FindOne(ctx, bson.M{
		"_id": hexUserID,
	}).Decode(&user)
	if err != nil {
		// if no instance of user found
		if errors.Is(err, mongo.ErrNoDocuments) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}	// else
		log.Printf("error fetching the users %v", err)
		http.Error(w, "internal Server error", http.StatusInternalServerError)
		return
	}

	// fmt.Println("r body", r.Body)
	// fmt.Println("r context", r.Context())

	json.NewEncoder(w).Encode(map[string]interface{}{
		"userId": userID,
		"user":   user,
	})
}

func GetAllUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// creating a context for furthur operations
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// finding all the data stored using userCollection
	cur, err := database.UserCollection.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
        return
	}
	defer cur.Close(ctx)

	// creating an array to store all the users
	// var users []map[string]any
	// for cur.Next(ctx) {
	// 	var u models.User
	// 	if err := cur.Decode(&u); err != nil {
	// 		http.Error(w, "internal server error", http.StatusInternalServerError)
    //     	return
	// 	}

	// 	users = append(users, map[string]any{
	// 		"id": u.ID.Hex(),
	// 		"name": u.Name,
	// 		"email": u.Email,
	// 		"createdAt": u.CreatedAt,
	// 		"updatedAt": u.UpdatedAt,
	// 	})
	// }

	// creating an array to store all the users
	var users []models.User
	for cur.Next(ctx) {
		var u models.User
		if err := cur.Decode(&u); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
        	return
		}
		users = append(users, u)
	}


	if err := cur.Err(); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
        return
	}

	json.NewEncoder(w).Encode(users)
}

func GetUserByID (w http.ResponseWriter, r *http.Request){
	w.Header().Set("Content-Type", "application/json")

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	params := mux.Vars(r)
	strID := params["id"]
	if strID == "" {
		http.Error(w, "missing user ID in params", http.StatusBadRequest)
        return
	}

	userID, err := primitive.ObjectIDFromHex(strID)
	if err != nil {
		http.Error(w, "error converting user ID", http.StatusBadRequest)
        return
	}

	var user models.User
	// Hello there

	err = database.UserCollection.FindOne(ctx, bson.M{
		"_id": userID,
	}).Decode(&user)
	if err != nil {
		http.Error(w, "user not found", http.StatusBadRequest)
        return
	}

	json.NewEncoder(w).Encode(user)
}