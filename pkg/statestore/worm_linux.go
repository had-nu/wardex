// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build linux

package statestore

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func lockFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("statestore: open for lock: %w", err)
	}
	defer f.Close()

	// FS_IMMUTABLE_FL = 0x00000010 (from linux/fs.h)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		0x8008660C, // FS_IOC_SETFLAGS
		uintptr(unsafe.Pointer(&struct{ flags uint32 }{0x00000010})),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("statestore: set immutable: %w", errno)
	}
	return nil
}

func isLocked(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("statestore: open for check: %w", err)
	}
	defer f.Close()

	var flags struct{ flags uint32 }
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		0x80046601, // FS_IOC_GETFLAGS
		uintptr(unsafe.Pointer(&flags)),
		0, 0, 0,
	)
	if errno != 0 {
		return false, fmt.Errorf("statestore: get immutable: %w", errno)
	}
	return flags.flags&0x00000010 != 0, nil
}

func unlockFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("statestore: open for unlock: %w", err)
	}
	defer f.Close()

	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		0x8008660C, // FS_IOC_SETFLAGS
		uintptr(unsafe.Pointer(&struct{ flags uint32 }{0})),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("statestore: clear immutable: %w", errno)
	}
	return nil
}
