package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RotatingWriter struct {
	file       *os.File
	filepath   string
	maxSize    int64
	maxAge     time.Duration
	maxBackups int
	currentSize int64
	mutex       sync.Mutex
}

func NewRotatingWriter(filepath string, maxSize int64, maxAge time.Duration, maxBackups int) (*RotatingWriter, error) {
	if err := os.MkdirAll(filepath, 0755); err != nil {
		return nil, err
	}

	rw := &RotatingWriter{
		filepath:   filepath,
		maxSize:    maxSize,
		maxAge:     maxAge,
		maxBackups: maxBackups,
	}

	if err := rw.openFile(); err != nil {
		return nil, err
	}

	go rw.cleanupOldFiles()

	return rw, nil
}

func (rw *RotatingWriter) Write(data []byte) (int, error) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	if rw.shouldRotate() {
		if err := rw.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := rw.file.Write(data)
	rw.currentSize += int64(n)
	return n, err
}

func (rw *RotatingWriter) Close() error {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	if rw.file != nil {
		return rw.file.Close()
	}
	return nil
}

func (rw *RotatingWriter) shouldRotate() bool {
	return rw.currentSize >= rw.maxSize
}

func (rw *RotatingWriter) rotate() error {
	if rw.file != nil {
		rw.file.Close()
	}

	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s", rw.filepath, timestamp)

	if err := os.Rename(rw.filepath, backupPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	rw.currentSize = 0
	return rw.openFile()
}

func (rw *RotatingWriter) openFile() error {
	file, err := os.OpenFile(rw.filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	rw.file = file

	stat, err := file.Stat()
	if err != nil {
		return err
	}
	rw.currentSize = stat.Size()

	return nil
}

func (rw *RotatingWriter) cleanupOldFiles() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		rw.cleanup()
	}
}

func (rw *RotatingWriter) cleanup() {
	dir := filepath.Dir(rw.filepath)
	base := filepath.Base(rw.filepath)

	files, err := filepath.Glob(filepath.Join(dir, base+".*"))
	if err != nil {
		return
	}

	now := time.Now()
	var toDelete []string

	for _, file := range files {
		stat, err := os.Stat(file)
		if err != nil {
			continue
		}

		if rw.maxAge > 0 && now.Sub(stat.ModTime()) > rw.maxAge {
			toDelete = append(toDelete, file)
		}
	}

	if len(files) > rw.maxBackups {
		excess := len(files) - rw.maxBackups
		for i := 0; i < excess && i < len(files); i++ {
			toDelete = append(toDelete, files[i])
		}
	}

	for _, file := range toDelete {
		os.Remove(file)
	}
}

func ParseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	
	multiplier := int64(1)
	if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = s[:len(s)-2]
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = s[:len(s)-2]
	} else if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-2]
	} else if strings.HasSuffix(s, "B") {
		s = s[:len(s)-1]
	}

	size, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}

	return size * multiplier, nil
}

func ParseDuration(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(s[:len(s)-1])
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
}

type LogFormatter interface {
	Format(entry *Entry) ([]byte, error)
}

type JSONFormatter struct{}

func (jf *JSONFormatter) Format(entry *Entry) ([]byte, error) {
	return json.Marshal(entry)
}

type TextFormatter struct {
	TimestampFormat string
}

func (tf *TextFormatter) Format(entry *Entry) ([]byte, error) {
	format := tf.TimestampFormat
	if format == "" {
		format = "2006-01-02T15:04:05.000Z07:00"
	}

	line := fmt.Sprintf("[%s] %s %s %s %s - %d %s\n",
		entry.Timestamp.Format(format),
		entry.Request.IP,
		entry.User.Email,
		entry.Request.Method,
		entry.Request.Path,
		entry.Response.Status,
		entry.Decision.Action,
	)

	return []byte(line), nil
}