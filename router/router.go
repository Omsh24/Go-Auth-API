package router

import (
	"net/http"

	"github.com/Omsh24/pokedexSLice/controller"
	"github.com/Omsh24/pokedexSLice/middleware"
	"github.com/gorilla/mux"
)

func Router() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/", controller.DefaultPath)

	// public routes
	// handle func takes in a path and a function to lead to when gone on that path
	router.HandleFunc("/api/signup", controller.Signup).Methods("POST")
	router.HandleFunc("/api/login", controller.Login).Methods("POST")
	router.HandleFunc("/api/logout", controller.Logout).Methods("GET")
	router.HandleFunc("/api/users", controller.GetAllUsers).Methods("GET")
	router.HandleFunc("/api/user/{id}", controller.GetUserByID).Methods("GET")

	// private routes -> require authentication 
	// Handle takes in a path and a handler (not a func)
	router.Handle(
		"/api/home",
		// authentication function takes in a http.handler and returns a http.handler
		middleware.Authenticator(http.HandlerFunc(controller.Home)),
	).Methods("GET")

	return router
}