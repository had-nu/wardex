// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build windows

package statestore

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modkernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procSetFileInformationByHandle = modkernel32.NewProc("SetFileInformationByHandle")
)

const (
	fileReadAttributes           = 0x0080
	fileWriteAttributes          = 0x0100
	fileAttributeReadonly uint32 = 0x00000001
	fileInfoClassBasic           = 1
)

// fileBasicInfo mirrors the Windows FILE_BASIC_INFO structure.
type fileBasicInfo struct {
	CreationTime   syscall.Filetime
	LastAccessTime syscall.Filetime
	LastWriteTime  syscall.Filetime
	ChangeTime     syscall.Filetime
	FileAttributes uint32
	_              [4]byte
}

func lockFile(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("statestore: UTF16: %w", err)
	}

	handle, err := syscall.CreateFile(
		name,
		fileWriteAttributes|fileReadAttributes,
		0, nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("statestore: open for lock: %w", err)
	}
	defer syscall.CloseHandle(handle)

	var info fileBasicInfo
	err = syscall.GetFileInformationByHandle(handle, (*syscall.ByHandleFileInformation)(unsafe.Pointer(&info)))
	if err != nil {
		return fmt.Errorf("statestore: get info: %w", err)
	}

	info.FileAttributes |= fileAttributeReadonly
	r, _, callErr := procSetFileInformationByHandle.Call(
		uintptr(handle),
		fileInfoClassBasic,
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)
	if r == 0 {
		if callErr != nil {
			return fmt.Errorf("statestore: set readonly: %w", callErr)
		}
		return fmt.Errorf("statestore: set readonly: unknown error")
	}
	return nil
}

func isLocked(path string) (bool, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, fmt.Errorf("statestore: UTF16: %w", err)
	}

	handle, err := syscall.CreateFile(
		name,
		fileReadAttributes,
		0, nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return false, fmt.Errorf("statestore: open for check: %w", err)
	}
	defer syscall.CloseHandle(handle)

	var info fileBasicInfo
	err = syscall.GetFileInformationByHandle(handle, (*syscall.ByHandleFileInformation)(unsafe.Pointer(&info)))
	if err != nil {
		return false, fmt.Errorf("statestore: get info: %w", err)
	}

	return info.FileAttributes&fileAttributeReadonly != 0, nil
}

func unlockFile(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("statestore: UTF16: %w", err)
	}

	handle, err := syscall.CreateFile(
		name,
		fileWriteAttributes|fileReadAttributes,
		0, nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("statestore: open for unlock: %w", err)
	}
	defer syscall.CloseHandle(handle)

	var info fileBasicInfo
	err = syscall.GetFileInformationByHandle(handle, (*syscall.ByHandleFileInformation)(unsafe.Pointer(&info)))
	if err != nil {
		return fmt.Errorf("statestore: get info: %w", err)
	}

	info.FileAttributes &^= fileAttributeReadonly
	r, _, callErr := procSetFileInformationByHandle.Call(
		uintptr(handle),
		fileInfoClassBasic,
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)
	if r == 0 {
		if callErr != nil {
			return fmt.Errorf("statestore: clear readonly: %w", callErr)
		}
		return fmt.Errorf("statestore: clear readonly: unknown error")
	}
	return nil
}
