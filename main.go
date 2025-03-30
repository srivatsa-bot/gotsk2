package main

import (
	"log"
	"net/http"

	"github.com/srivatsa-bot/gotsk2/handlers"
)

func init() { //runs when program strats before main once
	handlers.InitDb()
}

func main() {
	defer handlers.Db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handlers.Login)
	mux.HandleFunc("/register", handlers.Register)
	mux.HandleFunc("/upload", handlers.Auth(handlers.Upload))
	mux.HandleFunc("/files", handlers.Auth(handlers.ListFiles))
	mux.HandleFunc("/share/", handlers.Auth(handlers.ShareFile))

	port := ":8080"
	log.Printf("Starting server on port %s", port)
	err := http.ListenAndServe(port, mux)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
