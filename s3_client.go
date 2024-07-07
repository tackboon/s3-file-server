package main

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Client struct {
	Client *s3.Client
	Bucket string
}

func NewS3Client(awsAccessKey string, awsAccessSecret string, awsRegion string, s3Accelerate bool, s3Bucket string) S3Client {
	// load s3 config
	credential := aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(awsAccessKey, awsAccessSecret, ""))
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion), config.WithCredentialsProvider(credential))
	if err != nil {
		log.Fatalf("failed to init s3 client, err: %v", err)
	}

	// create s3 client
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UseAccelerate = s3Accelerate
	})

	return S3Client{Client: client, Bucket: s3Bucket}
}

func (s S3Client) HeadObject(ctx context.Context, objectKey string) (*s3.HeadObjectOutput, error) {
	objInput := &s3.HeadObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objectKey),
	}

	return s.Client.HeadObject(ctx, objInput)
}

func (s S3Client) GetRangeObject(ctx context.Context, objectKey string, requestedRange string) (*s3.GetObjectOutput, error) {
	input := s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objectKey),
		Range:  aws.String(requestedRange),
	}

	return s.Client.GetObject(ctx, &input)
}

func (s S3Client) GetObjectTagging(ctx context.Context, objectKey string) (map[string]string, error) {
	input := s3.GetObjectTaggingInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objectKey),
	}

	tags, err := s.Client.GetObjectTagging(ctx, &input)
	if err != nil {
		return nil, err
	}

	out := make(map[string]string)
	for _, tag := range tags.TagSet {
		out[*tag.Key] = *tag.Value
	}

	return out, nil
}
