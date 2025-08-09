package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// WritePidFile writes pid file atomically if possible.
func WritePidFile(path string, pid int) error {
	pidStr := []byte(strconv.Itoa(pid))

	if fileExists(path) {
		// If path exists, write in place, because file could be pipe or something.
		if err := os.WriteFile(path, pidStr, 0644); err != nil {
			return fmt.Errorf("failed to write pid file %s: %w", path, err)
		}
	} else {
		// Otherwise write using temp file to make write atomic.
		b := make([]byte, 8)
		_, err := rand.Read(b)
		if err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}
		tempPath := path + fmt.Sprintf(".%x", hex.EncodeToString(b))

		if err := os.WriteFile(tempPath, pidStr, 0644); err != nil {
			return fmt.Errorf("failed to write temp pid file %s: %w", tempPath, err)
		}

		if err := os.Rename(tempPath, path); err != nil {
			return fmt.Errorf("failed to rename temp pid file %s -> %s: %w", tempPath, path, err)
		}
	}

	return nil
}
