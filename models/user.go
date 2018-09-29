package models

import "gopkg.in/mgo.v2/bson"

//User
type User struct {
	ID       bson.ObjectId `bson:"_id" json:"id"`
	Name     string        `bson:"name" json:"name"`
	Email    string        `bson:"email" json:"email"`
	Avatar   string        `bson:"avatar" json:"avatar"`
	Password string        `bson:"password" json:"password"`
}
