package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Omsh24/pokedexSLice/database"
	"github.com/Omsh24/pokedexSLice/router"
	"github.com/joho/godotenv"
)

func main() {
	// loading the .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	

	// connecting the databse
	database.ConnectDB()

	// connecting the router
	r := router.Router()

	// verifying that the server has started, also implementing PORT from .env
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT env variable not set")
	}

	log.Println("Server is getting started at", port)
	portRoute := ":" + port
	log.Fatal(http.ListenAndServe(portRoute, r))
}