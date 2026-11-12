package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const fileCleanupInterval = time.Minute

// CleanFileWatch preserves the existing entry point. Main uses the cancellable
// worker so both subscriptions and reconciliation stop during shutdown.
func CleanFileWatch() { RunFileCleanup(context.Background()) }

func RunFileCleanup(ctx context.Context) { runFileCleanup(ctx, fileCleanupInterval) }
func runFileCleanup(ctx context.Context, interval time.Duration) {
	done := make(chan struct{})
	go func() { defer close(done); watchFileExpirations(ctx) }()
	defer func() { <-done }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := CleanupExpiredArchives(ctx); err != nil && ctx.Err() == nil {
			log.WithError(err).Warn("Archive reconciliation failed; existing files retained on Redis errors")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func cleanupConnection(ctx context.Context, timeout time.Duration) (redis.Conn, error) {
	db, err := strconv.Atoi(REDIS_DB)
	if err != nil {
		return nil, fmt.Errorf("invalid cleanup Redis database: %w", err)
	}
	opts := []redis.DialOption{redis.DialConnectTimeout(3 * time.Second), redis.DialReadTimeout(timeout), redis.DialWriteTimeout(3 * time.Second), redis.DialDatabase(db)}
	if REDIS_PASSWORD != "" {
		opts = append(opts, redis.DialPassword(REDIS_PASSWORD))
	}
	return redis.DialContext(ctx, "tcp", net.JoinHostPort(REDIS_HOST, REDIS_PORT), opts...)
}
func canonicalArchiveID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id.String() == value
}

// CleanupExpiredArchives repairs missed expiry notifications, including outages
// and restarts. It only considers regular <canonical UUID>.zip files in data.
// A Redis failure is never interpreted as an expired record.
func CleanupExpiredArchives(ctx context.Context) error {
	guard, err := AcquireStoragePathGuard(FILEFOLDER)
	if err != nil {
		return err
	}
	defer guard.Close()
	entries, err := os.ReadDir(FILEFOLDER)
	if err != nil {
		return err
	}
	c, err := cleanupConnection(ctx, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	return reconcileArchives(ctx, c, entries)
}
func reconcileArchives(ctx context.Context, c redis.Conn, entries []os.DirEntry) error {
	return reconcileArchivesWith(ctx, c, entries, removeExpiredArchive)
}

func reconcileArchivesWith(ctx context.Context, c redis.Conn, entries []os.DirEntry, remove func(redis.Conn, string) error) error {
	var failures error
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return errors.Join(failures, err)
		}
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".zip") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".zip")
		if !canonicalArchiveID(id) {
			continue
		}
		if err := remove(c, id); err != nil {
			failures = errors.Join(failures, err)
		}
	}
	return failures
}
func removeExpiredArchive(c redis.Conn, id string) error {
	if !canonicalArchiveID(id) {
		return fmt.Errorf("invalid archive identifier")
	}
	guard, err := AcquireStoragePathGuard(FILEFOLDER)
	if err != nil {
		return err
	}
	defer guard.Close()
	exists, err := redis.Bool(c.Do("EXISTS", REDIS_PREFIX+"file_"+id))
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	path := filepath.Join(FILEFOLDER, id+".zip")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if strings.EqualFold(os.Getenv("OKURU_CLEANUP_DRY_RUN"), "true") {
		log.WithField("archive", id+".zip").Warn("Cleanup dry-run: expired archive would be removed")
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
func watchFileExpirations(ctx context.Context) {
	delay := time.Second
	for ctx.Err() == nil {
		err := receiveFileExpirations(ctx)
		if ctx.Err() != nil {
			return
		}
		log.WithError(err).Warn("Archive expiry subscription disconnected; reconciliation remains active")
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}
func receiveFileExpirations(ctx context.Context) error {
	c, err := cleanupConnection(ctx, 0)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	psc := redis.PubSubConn{Conn: c}
	db, err := strconv.Atoi(REDIS_DB)
	if err != nil {
		return err
	}
	channel := "__keyevent@" + strconv.Itoa(db) + "__:expired"
	if err := psc.Subscribe(channel); err != nil {
		return err
	}
	for {
		switch event := psc.Receive().(type) {
		case redis.Message:
			prefix := REDIS_PREFIX + "file_"
			key := string(event.Data)
			if event.Channel != channel || !strings.HasPrefix(key, prefix) {
				continue
			}
			id := strings.TrimPrefix(key, prefix)
			if !canonicalArchiveID(id) {
				continue
			}
			check, err := cleanupConnection(ctx, 3*time.Second)
			if err != nil {
				return err
			}
			err = removeExpiredArchive(check, id)
			check.Close()
			if err != nil {
				return err
			}
		case error:
			return event
		}
	}
}
