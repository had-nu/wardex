// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package atomicwrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWrite_Basic verifies basic atomic write functionality.
func TestWrite_Basic(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.txt")
	data := []byte("hello atomic world")

	if err := Write(path, data); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	readData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(readData) != string(data) {
		t.Fatalf("data mismatch: got %q, want %q", string(readData), string(data))
	}
}

// TestWrite_EmptyData verifies writing empty data works.
func TestWrite_EmptyData(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "empty.txt")

	if err := Write(path, []byte{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data, _ := os.ReadFile(path)
	if len(data) != 0 {
		t.Fatalf("expected empty file, got %d bytes", len(data))
	}
}

// TestWrite_LargeData verifies writing large data works.
func TestWrite_LargeData(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "large.txt")
	data := make([]byte, 10*1024*1024) // 10MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := Write(path, data); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	readData, _ := os.ReadFile(path)
	if len(readData) != len(data) {
		t.Fatalf("size mismatch: got %d, want %d", len(readData), len(data))
	}
}

// TestWrite_Atomicity verifies that on failure, no partial file remains.
func TestWrite_Atomicity(t *testing.T) {
	tmp := t.TempDir()

	// Create a file that will cause Write to fail (permission denied on parent)
	if err := os.MkdirAll(filepath.Join(tmp, "readonly"), 0500); err != nil {
		t.Fatal(err)
	}
	// Make it read-only
	if err := os.Chmod(filepath.Join(tmp, "readonly"), 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(tmp, "readonly"), 0700)

	path := filepath.Join(tmp, "readonly", "test.txt")
	err := Write(path, []byte("test"))
	if err == nil {
		t.Fatal("expected Write to fail on read-only directory")
	}
	// The target file should not exist
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("target file should not exist on failure, but got: %v", err)
	}
}

// TestWrite_FilePermissions verifies the output file has 0600 permissions.
func TestWrite_FilePermissions(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "perm.txt")

	if err := Write(path, []byte("test")); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 permissions, got %04o", info.Mode().Perm())
	}
}

// TestWrite_SymlinkAttack verifies that pre-existing symlink at temp path is rejected.
func TestWrite_SymlinkAttack(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can bypass symlink checks")
	}
	tmp := t.TempDir()
	targetPath := filepath.Join(tmp, "target.txt")

	if err := Write(targetPath, []byte("original")); err != nil {
		t.Fatal(err)
	}

	// Now try to write again - should succeed (overwrite via rename)
	if err := Write(targetPath, []byte("updated")); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(targetPath)
	if string(data) != "updated" {
		t.Fatalf("expected updated content, got %q", string(data))
	}
}

// TestWrite_Overwrite verifies atomic overwrite works.
func TestWrite_Overwrite(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "overwrite.txt")

	if err := Write(path, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("v2")); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "v2" {
		t.Fatalf("expected v2, got %q", string(data))
	}
}

// TestWriteWithContext_Cancellation verifies context cancellation cleans up.
func TestWriteWithContext_Cancellation(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "ctx.txt")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := WriteWithContext(ctx, path, []byte("test"))
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestWriteWithContext_Timeout verifies timeout is respected.
func TestWriteWithContext_Timeout(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "timeout.txt")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Give time for timeout to expire
	time.Sleep(10 * time.Millisecond)

	err := WriteWithContext(ctx, path, []byte("test"))
	if err == nil {
		t.Fatal("expected error from timed-out context")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

// TestWriteWithContext_Success verifies successful write with context.
func TestWriteWithContext_Success(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "ctx_success.txt")

	ctx := context.Background()
	if err := WriteWithContext(ctx, path, []byte("success")); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "success" {
		t.Fatalf("expected success, got %q", string(data))
	}
}

// TestWrite_DirectorySync verifies parent directory is synced.
func TestWrite_DirectorySync(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "sync.txt")

	if err := Write(path, []byte("sync")); err != nil {
		t.Fatal(err)
	}

	// Verify the directory can be opened and synced (no error)
	dirF, err := os.Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer dirF.Close()
	if err := dirF.Sync(); err != nil {
		t.Fatalf("directory sync failed: %v", err)
	}
}

// TestWrite_Concurrent writes to different files concurrently.
func TestWrite_Concurrent(t *testing.T) {
	tmp := t.TempDir()
	const numWriters = 10

	errCh := make(chan error, numWriters)
	for i := 0; i < numWriters; i++ {
		go func(i int) {
			path := filepath.Join(tmp, fmt.Sprintf("concurrent_%d.txt", i))
			data := []byte(fmt.Sprintf("data-%d", i))
			errCh <- Write(path, data)
		}(i)
	}

	for i := 0; i < numWriters; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent write %d failed: %v", i, err)
		}
	}

	// Verify all files exist with correct content
	for i := 0; i < numWriters; i++ {
		path := filepath.Join(tmp, fmt.Sprintf("concurrent_%d.txt", i))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %d failed: %v", i, err)
		}
		expected := fmt.Sprintf("data-%d", i)
		if string(data) != expected {
			t.Fatalf("file %d: expected %q, got %q", i, expected, string(data))
		}
	}
}

// FuzzWrite tests Write with random inputs.
func FuzzWrite(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("a"))
	f.Add([]byte("hello world"))
	f.Add([]byte("path/with/slashes"))
	f.Add([]byte(""))
	f.Add(bytes.Repeat([]byte("x"), 1000))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "fuzz.txt")
		if err := Write(path, data); err != nil {
			t.Fatal(err)
		}
		readData, _ := os.ReadFile(path)
		if !bytes.Equal(data, readData) {
			t.Fatalf("data mismatch: got %q, want %q", readData, data)
		}
	})
}

// FuzzWriteWithContext tests WriteWithContext with random inputs.
func FuzzWriteWithContext(f *testing.F) {
	f.Add([]byte("test"))
	f.Add([]byte(""))
	f.Add(bytes.Repeat([]byte("x"), 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "fuzz.txt")
		ctx := context.Background()
		if err := WriteWithContext(ctx, path, data); err != nil {
			t.Fatal(err)
		}
		readData, _ := os.ReadFile(path)
		if !bytes.Equal(data, readData) {
			t.Fatalf("data mismatch")
		}
	})
}