package main

import (
	"log"
	"net/http"

	"github.com/Omsh24/pokedexSLice/database"
	"github.com/Omsh24/pokedexSLice/router"
	"github.com/joho/godotenv"
)

func main() {
	// loading the .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	database.ConnectDB()

	r := router.Router()

	log.Println("Server is getting started")
	log.Fatal(http.ListenAndServe(":9000", r))

}