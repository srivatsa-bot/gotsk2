package storage

import (
	"fmt"
	"log"
	"mime/multipart"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

const (
	AWS_S3_REGION = ""
	AWS_S3_BUCKET = ""
)

var sess = connectAWS()

// connect to aws throug aws-sdk-go
func connectAWS() *session.Session {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(AWS_S3_REGION),
		Credentials: credentials.NewStaticCredentials("", "", ""),
	})
	if err != nil {
		log.Fatalf("failed to connect to AWS: %v\n", err)
	}
	return sess
}

// upload a file to S3
// for large files aws-sdk will split the file and concurrently upload it
func UploadToS3(file multipart.File, header *multipart.FileHeader, username string) (string, string, error) {
	// generate a unique filename
	filename := fmt.Sprintf("%s/%s", username, header.Filename)

	//uploader from sdk
	uploader := s3manager.NewUploader(sess)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(AWS_S3_BUCKET),
		Key:    aws.String(filename),
		Body:   file,
	})

	// Handle upload errors
	if err != nil {
		log.Printf("Failed to upload %s: %v", header.Filename, err)
		return "", "", fmt.Errorf("failed to upload file: %w", err)
	}

	publicURL := fmt.Sprintf("https://%s.s3.amazonaws.com/%s", AWS_S3_BUCKET, filename)

	log.Printf("File uploaded successfully: %s", filename)
	return filename, publicURL, nil
}
