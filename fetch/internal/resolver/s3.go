package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Resolver fetches artifacts from S3-compatible object storage, which
// covers AWS S3, OpenShift Data Foundation, and MinIO. URI form:
// s3://bucket/prefix
//
// Credentials come from the standard environment (AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_S3_ENDPOINT) that the scan job
// projects from the model's connection Secret.
type S3Resolver struct {
	// Limits bounds what is fetched. Zero uses DefaultSamplingLimits.
	//
	// Object storage is where models actually live in a cluster, so this is the
	// backend where reading only the headers matters most.
	Limits SamplingLimits
}

// Scheme implements Resolver.
func (s *S3Resolver) Scheme() string { return "s3" }

// Resolve implements Resolver.
func (s *S3Resolver) Resolve(ctx context.Context, uri, destDir string) (*Artifact, error) {
	u, err := parseURL(uri)
	if err != nil {
		return nil, err
	}
	bucket := u.Host
	prefix := strings.TrimPrefix(u.Path, "/")
	if bucket == "" {
		return nil, fmt.Errorf("s3 URI %q is missing a bucket", uri)
	}

	client, err := newS3Client(ctx)
	if err != nil {
		return nil, err
	}
	// manager.Downloader is deprecated in favour of feature/s3/transfermanager,
	// which is still pre-GA. Migrating is deferred until the MinIO integration
	// test (make test-s3) can prove the replacement behaves identically against
	// real object storage; swapping it blind would trade a working path for an
	// unverified one.
	downloader := manager.NewDownloader(client) //nolint:staticcheck // SA1019: see note above

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("create staging dir: %w", err)
	}

	lim := s.Limits.withDefaults()
	cov := &Coverage{Skipped: map[string]string{}}

	var (
		total  int64
		files  int
		keys   []string
		hasher = sha256.New()
	)

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list s3://%s/%s: %w", bucket, prefix, err)
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if key == "" || strings.HasSuffix(key, "/") {
				continue
			}
			rel := strings.TrimPrefix(strings.TrimPrefix(key, prefix), "/")
			if rel == "" {
				rel = filepath.Base(key)
			}
			target, err := safeJoin(destDir, rel)
			if err != nil {
				return nil, err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, fmt.Errorf("create staging subdir: %w", err)
			}
			// Decide before moving any bytes. A bucket holding a frontier
			// model is hundreds of gigabytes of tensor data whose only
			// inspectable part is a header at byte zero; pulling it whole to
			// read that header is the difference between a scan costing
			// kilobytes and costing the model.
			size := aws.ToInt64(obj.Size)
			what, why := planFor(rel, size, total, lim)
			if what == planSkip {
				cov.Skipped[rel] = why
				keys = append(keys, fmt.Sprintf("%s:%s", key, aws.ToString(obj.ETag)))
				continue
			}

			var n int64
			if what == planHeader {
				body, err := sampleHeader(rel, func(_ string, off, length int64) ([]byte, error) {
					return s3Range(ctx, client, bucket, key, off, length)
				}, lim.HeaderBytes)
				if err != nil {
					return nil, err
				}
				if err := os.WriteFile(target, body, 0o644); err != nil {
					return nil, fmt.Errorf("write %s: %w", target, err)
				}
				n = int64(len(body))
				cov.HeaderOnly = append(cov.HeaderOnly, rel)
			} else {
				f, err := os.Create(target)
				if err != nil {
					return nil, fmt.Errorf("create %s: %w", target, err)
				}
				n, err = downloader.Download(ctx, f, &s3.GetObjectInput{ //nolint:staticcheck // SA1019: see newS3Client note
					Bucket: aws.String(bucket),
					Key:    aws.String(key),
				})
				closeErr := f.Close()
				if err != nil {
					return nil, fmt.Errorf("download s3://%s/%s: %w", bucket, key, err)
				}
				if closeErr != nil {
					return nil, fmt.Errorf("close %s: %w", target, closeErr)
				}
				cov.FetchedWhole = append(cov.FetchedWhole, rel)
			}
			total += n
			files++
			keys = append(keys, fmt.Sprintf("%s:%s", key, aws.ToString(obj.ETag)))
			if files >= lim.MaxFiles {
				break
			}
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no objects found at s3://%s/%s", bucket, prefix)
	}

	// Object storage has no native digest for a multi-object prefix, so the
	// artifact identity is a stable hash over the object keys and ETags.
	sort.Strings(keys)
	for _, k := range keys {
		hasher.Write([]byte(k))
	}

	// A partial fetch has to say so. A scan that read a header and reported
	// nothing is not the same as a scan that read the file and found nothing,
	// and the difference has to survive into the report or the optimisation is
	// bought with a lie.
	sort.Strings(cov.HeaderOnly)
	sort.Strings(cov.FetchedWhole)

	return &Artifact{
		URI:       uri,
		Digest:    "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		MediaType: "application/vnd.assay.model-prefix",
		LocalPath: destDir,
		SizeBytes: total,
		Coverage:  cov,
	}, nil
}

func newS3Client(ctx context.Context) (*s3.Client, error) {
	var loadOpts []func(*awsconfig.LoadOptions) error

	if region := firstEnv("AWS_REGION", "AWS_DEFAULT_REGION"); region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(region))
	} else {
		// ODF and MinIO ignore the region but the SDK requires one.
		loadOpts = append(loadOpts, awsconfig.WithRegion("us-east-1"))
	}

	if key, secret := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"); key != "" && secret != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(key, secret, os.Getenv("AWS_SESSION_TOKEN")),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	endpoint := firstEnv("AWS_S3_ENDPOINT", "S3_ENDPOINT")
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			if !strings.Contains(endpoint, "://") {
				endpoint = "https://" + endpoint
			}
			o.BaseEndpoint = aws.String(endpoint)
			// Non-AWS S3 implementations generally require path-style access.
			o.UsePathStyle = true
		}
	}), nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// s3Range reads one byte range of an object.
//
// The whole point of the sampling strategy: a safetensors header is a few
// kilobytes at offset zero, and S3 will serve exactly those bytes rather than
// the forty gigabytes behind them.
func s3Range(ctx context.Context, client *s3.Client, bucket, key string, off, length int64) ([]byte, error) {
	if length <= 0 {
		return nil, nil
	}
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", off, off+length-1)),
	})
	if err != nil {
		return nil, fmt.Errorf("range read s3://%s/%s: %w", bucket, key, err)
	}
	defer out.Body.Close()
	return io.ReadAll(io.LimitReader(out.Body, length))
}
