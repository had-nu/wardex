// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build darwin

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

	// UF_IMMUTABLE = 0x00000002 (from sys/flags.h)
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		0x80046602, // FS_IOC_GETFLAGS
		uintptr(unsafe.Pointer(&struct{ flags uint32 }{0x00000002})),
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
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		0x80046602, // FS_IOC_GETFLAGS
		uintptr(unsafe.Pointer(&flags)),
	)
	if errno != 0 {
		return false, fmt.Errorf("statestore: get immutable: %w", errno)
	}
	return flags.flags&0x00000002 != 0, nil
}

func unlockFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("statestore: open for unlock: %w", err)
	}
	defer f.Close()

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		0x80046602, // FS_IOC_GETFLAGS
		uintptr(unsafe.Pointer(&struct{ flags uint32 }{0})),
	)
	if errno != 0 {
		return fmt.Errorf("statestore: clear immutable: %w", errno)
	}
	return nil
}
