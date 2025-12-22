package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type SignupTemplate struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginTemplate struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type MyDex struct {
	PokemonName  string   `bson:"pokemonName" json:"pokemonName"`
	PokemonImage string   `bson:"pokemonImage" json:"pokemonImage"`
	Types        []string `bson:"types" json:"types"`
}

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name         string             `bson:"name" json:"name"`
	Email        string             `bson:"email" json:"email"`
	PasswordHash string             `bson:"passwordHash" json:"-"`
	Mydex        []MyDex            `bson:"mydex" json:"mydex"`
	CreatedAt    time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt    time.Time          `bson:"updatedAt" json:"updatedAt"`
}
