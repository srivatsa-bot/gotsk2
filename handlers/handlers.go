package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"github.com/srivatsa-bot/gotsk2/storage"
)

var jwtKey = []byte("my_super_secret_key") //my priv key

// check for db conection
var Db *sql.DB

// initail func to check db connection
func InitDb() { //runs when program strats before main once
	connstr := "postgresql://user:password@localhost:5432/dbname?sslmode=disable"
	var err error
	Db, err = sql.Open("postgres", connstr)
	if err != nil {
		log.Fatal(err)
	}

	err = Db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("database connected")
}

//json data struct

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// for creating jwt
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// handler to register
func Register(w http.ResponseWriter, r *http.Request) {
	//only allow post
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Check if username already exists in db
	var exists bool
	err = Db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", creds.Username).Scan(&exists)
	if err != nil {
		log.Printf("error checking username : %v\n", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	//if true
	if exists {
		http.Error(w, "username already exists", http.StatusConflict)
		return
	}

	// if flase, insert new user
	_, err = Db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", creds.Username, creds.Password)
	if err != nil {
		log.Printf("error creating user: %v\n", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("user registered: %s\n", creds.Username)
	w.WriteHeader(http.StatusCreated)

	//send sucess msg to user
	json.NewEncoder(w).Encode(map[string]string{
		"message": "user registered successfully",
	})
}

// Handler to login
func Login(w http.ResponseWriter, r *http.Request) {
	//only post
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	//db trans
	var dbPassword string
	err = Db.QueryRow("SELECT password FROM users WHERE username=$1", creds.Username).Scan(&dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "invalid user or password", http.StatusUnauthorized)
		} else {
			log.Printf("error querying user: %v\n", err)
			http.Error(w, "user doesn't exist", http.StatusInternalServerError)
		}
		return
	}

	//comparing passcodes from db with
	if dbPassword != creds.Password {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	//setup for jwt token
	expirationTime := time.Now().Add(15 * time.Minute) //15min for now
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "Srivatsa(22BCE3825)",
		},
	}

	//creating new token with claims docunment
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//sign this tocken with my priv key to make it public key
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Printf("error generating token: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("user logged in successfully: %s", creds.Username)

	//send the token as a cookie to user
	//cookie cannot be accesed through in js if httponly flag is turned on
	http.SetCookie(w, &http.Cookie{
		Name:     "token", //cookie name
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Path:     "/",
	})

	//set authorization header
	w.Header().Set("Authorization", "Bearer "+tokenString)

	//send user the temp jwt token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

// middleware to auth the jwt token
func Auth(next http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var tokenString string

		// jwt are passed through auth header: Bearer <token>
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			//get tokenstring
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// if not found in header check the cookie
			cookie, err := r.Cookie("token")
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			tokenString = cookie.Value
		}

		// Parse and validate token
		claims := &Claims{}
		//decode token and extract claims int Claims struct and validate token
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) { //inteface is used to allow different return types by differnt algo like rsa,hs256. but i signed the key using hs256 which retuns a string keytype
			// validate signing method , only using hmac
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return jwtKey, nil
		})

		//handle error
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				http.Error(w, "invalid token signature", http.StatusUnauthorized)
				return
			}
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		//handle invalid token
		if !token.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		//context propagation, pass authentication data to next handlers, so they can access the user data
		// http req in go has default coontext, r.Context()
		//with value adds new key value pair to default context
		//to retrive a context use r.context().value("name")

		//for now use string for key value
		ctx := context.WithValue(r.Context(), "claims", claims)

		// calling next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// s3 stuff
// upload handler imporant
func Upload(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	//get username from jwt
	claims := r.Context().Value("claims").(*Claims)
	username := claims.Username //for metadata and db

	//set max file size as 50 mb, 50* 2^20 bytes = 50mb
	err := r.ParseMultipartForm(50 << 20)
	if err != nil {
		http.Error(w, "File size exceeds 50MB", http.StatusBadRequest)
		return
	}

	//get slice of files fomr the form
	//files is a slice of headers for the form
	files := r.MultipartForm.File["files"] //files="" in curl request
	if len(files) == 0 {
		http.Error(w, "no files provided", http.StatusBadRequest)
		return
	}

	//concurrey to upload more than one files, and we will rate limit it to 5 routines at a time

	var wg sync.WaitGroup

	//channel to collect data

	type uploadRes struct {
		Filename  string
		PublicURL string
		Timestamp time.Time
		Error     error
	}

	//channel to collect result msg
	results := make(chan uploadRes, len(files))

	//rate limited to only  5 times at a time

	sem := make(chan struct{}, 5)

	for _, fileHeader := range files {
		wg.Add(1)
		sem <- struct{}{} //accquire sem

		go func(header *multipart.FileHeader) {
			defer func() {
				<-sem //release sem
			}()
			defer wg.Done()

			//open the file header and read its contents
			file, err := header.Open()
			if err != nil {
				results <- uploadRes{Error: fmt.Errorf("error opening file %s: %v", header.Filename, err)}
				return
			}
			defer file.Close()

			//uplaod to s3 call UploadToS3 function
			filename, publicURL, err := storage.UploadToS3(file, header, username)
			if err != nil {
				results <- uploadRes{Error: fmt.Errorf("failed to upload file %s: %v", header.Filename, err)}
				return
			}

			//save metadat to postgres
			timestamp := time.Now()
			_, err = Db.Exec(
				"INSERT INTO file_uploads (username, filename, upload_time, file_url) VALUES ($1, $2, $3, $4)",
				username,
				filename,
				timestamp,
				publicURL,
			)

			//if failed to uplaod metadata
			if err != nil {
				results <- uploadRes{Error: fmt.Errorf("failed to save metadata for %s: %v", header.Filename, err)}
				return
			}

			//send to result chan
			results <- uploadRes{
				Filename:  filename,
				PublicURL: publicURL,
				Timestamp: timestamp,
				Error:     nil,
			}

		}(fileHeader)

	}
	//close res channel when all go rotimes are done

	go func() {
		wg.Wait()
		close(results)
	}()

	//collect results
	sucessUpload := []map[string]string{} //slice of mmaping to mimitate json
	failedUpload := []string{}

	for result := range results {
		if result.Error != nil {
			log.Printf("Upload error: %v\n", result.Error)
			failedUpload = append(failedUpload, result.Error.Error()) //error as string
		} else {
			sucessUpload = append(sucessUpload, map[string]string{
				"filename":  result.Filename,
				"publicURL": result.PublicURL,
				"timestamp": result.Timestamp.Format(time.RFC3339),
			})
		}
	}

	//retunr response to user
	// Return response
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message":           "File upload process completed",
		"successfulUploads": sucessUpload,
		"totalSuccessful":   len(sucessUpload),
		"totalFailed":       len(failedUpload),
	}

	if len(failedUpload) > 0 {
		response["failedUploads"] = failedUpload //sends a slice of failed files
	}

	json.NewEncoder(w).Encode(response)

}

// list all the files uploaded by user
func ListFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// user name from jwt
	claims := r.Context().Value("claims").(*Claims)
	username := claims.Username

	// query db for user metadata
	rows, err := Db.Query(
		"SELECT filename, upload_time, file_url FROM file_uploads WHERE username = $1 ORDER BY upload_time DESC",
		username,
	)
	if err != nil {
		log.Printf("failed to query files: %v", err)
		http.Error(w, "failed to retrieve files", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Build response
	type FileInfo struct {
		Filename   string    `json:"filename"`
		UploadTime time.Time `json:"uploadTime"`
		FileURL    string    `json:"fileUrl"`
	}

	//scan rows from select statement
	var files []FileInfo
	//scan evey row returned by sql
	for rows.Next() {
		var file FileInfo
		//copy column values
		err := rows.Scan(&file.Filename, &file.UploadTime, &file.FileURL)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}
		files = append(files, file)
	}
	// Return file list
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //interface takes in any type of data
		"files": files, //return the json struct
	})
}

func ShareFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	//get user
	claims := r.Context().Value("claims").(*Claims)
	username := claims.Username

	// extract filename from URL path /share/{filename}
	//eg - share/sri.pdf
	//split splits at /share/. and output is ["","sri.pdf"].
	//for now handles only one file
	path := r.URL.Path
	parts := strings.Split(path, "/share/")
	if len(parts) != 2 || parts[1] == "" {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	reqFile := parts[1]

	// Check if the file exists and belongs to the user
	var fileURL string
	var filename string
	err := Db.QueryRow(
		"SELECT filename, file_url FROM file_uploads WHERE username = $1 AND filename LIKE $2",
		username, "%"+reqFile,
	).Scan(&filename, &fileURL)
	//here we used %reqFile which is wildcard in psql will retun files that contain reqfile name

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "file not found", http.StatusNotFound)
		} else {
			log.Printf("DB error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		return
	}

	// Return the shareable link
	w.Header().Set("Content-Type", "application/json")
	//send result in key value pair
	json.NewEncoder(w).Encode(map[string]string{
		"message":      "File shared successfully",
		"filename":     filename,
		"shareableURL": fileURL,
	})
}
