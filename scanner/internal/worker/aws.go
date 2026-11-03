package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"
)

// S3Objects opens objects in one bucket. Reads are range requests made with the
// context Open was given, so a job's timeout also bounds its reads.
type S3Objects struct {
	Client *s3.Client
	Bucket string
}

func (o *S3Objects) Open(ctx context.Context, key string) (io.ReaderAt, int64, error) {
	head, err := o.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &o.Bucket, Key: &key})
	if err != nil {
		return nil, 0, fmt.Errorf("stored object: %w", err)
	}
	size := aws.ToInt64(head.ContentLength)
	// Pinned to the version measured, so a concurrent write cannot mix two objects.
	return &s3Range{ctx: ctx, o: o, key: key, version: head.VersionId, size: size}, size, nil
}

type s3Range struct {
	ctx     context.Context
	o       *S3Objects
	key     string
	version *string
	size    int64
}

func (r *s3Range) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.size {
		return 0, io.EOF
	}
	want := min(int64(len(p)), r.size-off)
	rng := fmt.Sprintf("bytes=%d-%d", off, off+want-1)
	out, err := r.o.Client.GetObject(r.ctx, &s3.GetObjectInput{
		Bucket: &r.o.Bucket, Key: &r.key, VersionId: r.version, Range: &rng,
	})
	if err != nil {
		return 0, fmt.Errorf("reading the stored object: %w", err)
	}
	defer out.Body.Close()
	n, err := io.ReadFull(out.Body, p[:want])
	if err != nil {
		return n, fmt.Errorf("reading the stored object: %w", err)
	}
	if want < int64(len(p)) {
		return n, io.EOF
	}
	return n, nil
}

// KMSKeys unwraps data keys with the encryption context the gateway used, so a key
// only unwraps for the file it was made for.
type KMSKeys struct{ Client *kms.Client }

func (k *KMSKeys) Unwrap(ctx context.Context, fileID uuid.UUID, wrapped []byte, kmsKeyID string) ([]byte, error) {
	out, err := k.Client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:    wrapped,
		KeyId:             aws.String(kmsKeyID),
		EncryptionContext: map[string]string{"file_id": fileID.String()},
	})
	if err != nil {
		return nil, fmt.Errorf("unwrapping the data key: %w", err)
	}
	if len(out.Plaintext) != 32 {
		return nil, errors.New("unwrapping the data key: unexpected key size")
	}
	return out.Plaintext, nil
}

// SQSQueue receives from one SQS queue.
type SQSQueue struct {
	Client *sqs.Client
	URL    string
}

func (q *SQSQueue) Receive(ctx context.Context, max int) ([]Delivery, error) {
	out, err := q.Client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            &q.URL,
		MaxNumberOfMessages: int32(max),
		WaitTimeSeconds:     20, // long polling: an idle worker makes few requests
	})
	if err != nil {
		return nil, err
	}
	deliveries := make([]Delivery, 0, len(out.Messages))
	for _, m := range out.Messages {
		deliveries = append(deliveries, Delivery{Body: aws.ToString(m.Body), Handle: aws.ToString(m.ReceiptHandle)})
	}
	return deliveries, nil
}

func (q *SQSQueue) Delete(ctx context.Context, d Delivery) error {
	_, err := q.Client.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: &q.URL, ReceiptHandle: &d.Handle})
	return err
}

func (q *SQSQueue) Extend(ctx context.Context, d Delivery, visibility time.Duration) error {
	_, err := q.Client.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl: &q.URL, ReceiptHandle: &d.Handle, VisibilityTimeout: int32(visibility.Seconds()),
	})
	return err
}
