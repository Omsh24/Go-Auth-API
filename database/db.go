package database

import (
	"context"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var UserCollection *mongo.Collection

func ConnectDB(){
	// These two lines are used to connect to the DB
	clientOptions := options.Client().ApplyURI(os.Getenv("MONGO_URI"))
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// creating an instance of the databse to connect to in other files
	UserCollection = client.Database("pokedex").Collection("users")
	log.Println("MongoDB connection made")
}