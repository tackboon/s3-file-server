package main

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/joho/godotenv"
)

func main() {
	// load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("failed to load .env file")
	}

	awsAccessKey := os.Getenv("AWS_ACCESS_KEY")
	awsAccessSecret := os.Getenv("AWS_ACCESS_SECRET")
	awsRegion := os.Getenv("AWS_REGION")
	s3Accelerate := os.Getenv("S3_ACCELERATE") == "1"
	s3Bucket := os.Getenv("S3_BUCKET")
	xorKey := os.Getenv("XOR_KEY")
	aesKey := os.Getenv("AES_KEY")

	// connect to s3
	s3Client := NewS3Client(awsAccessKey, awsAccessSecret, awsRegion, s3Accelerate, s3Bucket)

	// create aes cipher block
	cipherBlock, err := NewAESCipher([]byte(aesKey))
	if err != nil {
		log.Fatal("failed to create aes cipher block")
	}

	// create file handler
	fileServer := NewHTTPFileServer(s3Client, xorKey, cipherBlock)

	// start file server
	http.HandleFunc("/xor/", fileServer.ServeXORFile)
	http.HandleFunc("/ctr/", fileServer.ServeCTRFile)
	log.Println("file server listening on port 8080 ...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("failed to start file server, err: %v", err)
	}
}

type HTTPFileServer struct {
	s3Client    S3Client
	xorKey      string
	cipherBlock cipher.Block
}

func NewHTTPFileServer(s3Client S3Client, xorKey string, cipherBlock cipher.Block) HTTPFileServer {
	return HTTPFileServer{
		s3Client:    s3Client,
		xorKey:      xorKey,
		cipherBlock: cipherBlock,
	}
}

func (h HTTPFileServer) ServeXORFile(w http.ResponseWriter, r *http.Request) {
	// get the s3 object key from url
	objKey := strings.TrimPrefix(r.URL.Path, "/xor/")

	// get the file size
	headObj, err := h.s3Client.HeadObject(r.Context(), objKey)
	if err != nil {
		var notFoundErr *types.NotFound
		if errors.As(err, &notFoundErr) {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fileSize := *headObj.ContentLength

	// get if modified since request header
	ifModifiedSince := r.Header.Get("If-Modified-Since")
	if ifModifiedSince != "" {
		parseTime, err := time.Parse(http.TimeFormat, ifModifiedSince)
		if err != nil {
			http.Error(w, "invalid If-Modified-Since header", http.StatusBadRequest)
			return
		}
		if !headObj.LastModified.After(parseTime) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	// get range request header
	var start int64 = 0
	var end int64 = fileSize - 1
	var isPartial bool = false

	requestedRange := r.Header.Get("Range")
	if requestedRange != "" {
		isPartial = true
		rangeParts := strings.Split(strings.TrimPrefix(requestedRange, "bytes="), "-")
		if len(rangeParts) == 2 {
			start, _ = strconv.ParseInt(rangeParts[0], 10, 64)
			if start < 0 {
				start = 0
			}

			end, _ = strconv.ParseInt(rangeParts[1], 10, 64)
			if end == 0 || end > fileSize {
				end = fileSize - 1
			}
		}
	}
	requestedRange = fmt.Sprintf("bytes=%d-%d", start, end)
	if start >= end {
		http.Error(w, "requested range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	// get s3 range object
	getObj, err := h.s3Client.GetRangeObject(r.Context(), objKey, requestedRange)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer getObj.Body.Close()

	// get if modified since request header
	ifUnmodifiedSince := r.Header.Get("If-Unmodified-Since")
	if ifUnmodifiedSince != "" {
		parseTime, err := time.Parse(http.TimeFormat, ifUnmodifiedSince)
		if err != nil {
			http.Error(w, "invalid If-Unmodified-Since header", http.StatusBadRequest)
			return
		}
		if !getObj.LastModified.Before(parseTime) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}

	// create a custom reader to decrypt the file
	xorReader := NewXorReader(getObj.Body, h.xorKey, start)

	// calculate content lenght
	contentLength := end - start + 1

	// write headers
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Type", *headObj.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLength))
	w.Header().Set("ETag", *getObj.ETag)
	w.Header().Set("Last-Modified", getObj.LastModified.Format(http.TimeFormat))

	status := http.StatusOK
	if isPartial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
		status = http.StatusPartialContent
	}

	w.WriteHeader(status)

	// serve the file
	if _, err := io.Copy(w, xorReader); err != nil {
		log.Printf("failed to serve file, object_key: %s, err: %v\n", objKey, err)
		return
	}
}

func (h HTTPFileServer) ServeCTRFile(w http.ResponseWriter, r *http.Request) {
	// get the s3 object key from url
	objKey := strings.TrimPrefix(r.URL.Path, "/ctr/")

	// get the file size
	headObj, err := h.s3Client.HeadObject(r.Context(), objKey)
	if err != nil {
		var notFoundErr *types.NotFound
		if errors.As(err, &notFoundErr) {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fileSize := *headObj.ContentLength
	realFileSize := fileSize - aes.BlockSize

	// get if modified since request header
	ifModifiedSince := r.Header.Get("If-Modified-Since")
	if ifModifiedSince != "" {
		parseTime, err := time.Parse(http.TimeFormat, ifModifiedSince)
		if err != nil {
			http.Error(w, "invalid If-Modified-Since header", http.StatusBadRequest)
			return
		}
		if !headObj.LastModified.After(parseTime) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	// get the iv
	ivObj, err := h.s3Client.GetRangeObject(r.Context(), objKey, fmt.Sprintf("bytes=0-%d", aes.BlockSize-1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer ivObj.Body.Close()

	iv := make([]byte, aes.BlockSize)
	if n, err := io.ReadFull(ivObj.Body, iv); err != nil || n != aes.BlockSize {
		http.Error(w, "failed to read iv", http.StatusInternalServerError)
		return
	}

	// get range request header
	var start int64 = 0
	var end int64 = realFileSize - 1
	var isPartial bool = false

	requestedRange := r.Header.Get("Range")
	if requestedRange != "" {
		isPartial = true
		rangeParts := strings.Split(strings.TrimPrefix(requestedRange, "bytes="), "-")
		if len(rangeParts) == 2 {
			start, _ = strconv.ParseInt(rangeParts[0], 10, 64)
			if start < 0 {
				start = 0
			}

			end, _ = strconv.ParseInt(rangeParts[1], 10, 64)
			if end == 0 || end >= realFileSize {
				end = realFileSize - 1
			}
		}
	}
	requestedRange = fmt.Sprintf("bytes=%d-%d", start+aes.BlockSize, end+aes.BlockSize)
	if start >= end {
		http.Error(w, "requested range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	// get s3 range object
	getObj, err := h.s3Client.GetRangeObject(r.Context(), objKey, requestedRange)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer getObj.Body.Close()

	// get if modified since request header
	ifUnmodifiedSince := r.Header.Get("If-Unmodified-Since")
	if ifUnmodifiedSince != "" {
		parseTime, err := time.Parse(http.TimeFormat, ifUnmodifiedSince)
		if err != nil {
			http.Error(w, "invalid If-Unmodified-Since header", http.StatusBadRequest)
			return
		}
		if !getObj.LastModified.Before(parseTime) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}

	ctrReader, err := NewCTRReader(getObj.Body, h.cipherBlock, iv, start)
	if err != nil {
		http.Error(w, "failed to create ctr reader", http.StatusInternalServerError)
		return
	}

	// calculate content lenght
	contentLength := end - start + 1

	// write headers
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Type", *headObj.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLength))
	w.Header().Set("ETag", *getObj.ETag)
	w.Header().Set("Last-Modified", getObj.LastModified.Format(http.TimeFormat))

	status := http.StatusOK
	if isPartial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize-aes.BlockSize))
		status = http.StatusPartialContent
	}

	w.WriteHeader(status)

	// serve the file
	if _, err := io.Copy(w, ctrReader); err != nil {
		log.Printf("failed to serve file, object_key: %s, err: %v\n", objKey, err)
		return
	}
}
