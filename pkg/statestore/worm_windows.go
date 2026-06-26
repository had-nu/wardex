// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build windows

package statestore

import (
	"fmt"
	"syscall"
	"unsafe"
)

func lockFile(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("statestore: UTF16: %w", err)
	}

	handle, err := syscall.CreateFile(
		name,
		syscall.FILE_WRITE_ATTRIBUTES|syscall.FILE_READ_ATTRIBUTES,
		0, nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("statestore: open for lock: %w", err)
	}
	defer syscall.CloseHandle(handle)

	var attrs syscall.FileBasicInfo
	_, err = syscall.GetFileInformationByHandle(handle, (*syscall.ByHandleFileInformation)(unsafe.Pointer(&attrs)))
	if err != nil {
		return fmt.Errorf("statestore: get info: %w", err)
	}

	attrs.FileAttributes |= syscall.FILE_ATTRIBUTE_READONLY
	_, err = syscall.SetFileInformationByHandle(handle, syscall.FileBasicInfoClass, (*byte)(unsafe.Pointer(&attrs)), uint32(unsafe.Sizeof(attrs)))
	if err != nil {
		return fmt.Errorf("statestore: set readonly: %w", err)
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
		syscall.FILE_READ_ATTRIBUTES,
		0, nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return false, fmt.Errorf("statestore: open for check: %w", err)
	}
	defer syscall.CloseHandle(handle)

	var attrs syscall.FileBasicInfo
	_, err = syscall.GetFileInformationByHandle(handle, (*syscall.ByHandleFileInformation)(unsafe.Pointer(&attrs)))
	if err != nil {
		return false, fmt.Errorf("statestore: get info: %w", err)
	}

	return attrs.FileAttributes&syscall.FILE_ATTRIBUTE_READONLY != 0, nil
}

func unlockFile(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("statestore: UTF16: %w", err)
	}

	handle, err := syscall.CreateFile(
		name,
		syscall.FILE_WRITE_ATTRIBUTES|syscall.FILE_READ_ATTRIBUTES,
		0, nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("statestore: open for unlock: %w", err)
	}
	defer syscall.CloseHandle(handle)

	var attrs syscall.FileBasicInfo
	_, err = syscall.GetFileInformationByHandle(handle, (*syscall.ByHandleFileInformation)(unsafe.Pointer(&attrs)))
	if err != nil {
		return fmt.Errorf("statestore: get info: %w", err)
	}

	attrs.FileAttributes &^= syscall.FILE_ATTRIBUTE_READONLY
	_, err = syscall.SetFileInformationByHandle(handle, syscall.FileBasicInfoClass, (*byte)(unsafe.Pointer(&attrs)), uint32(unsafe.Sizeof(attrs)))
	if err != nil {
		return fmt.Errorf("statestore: clear readonly: %w", err)
	}
	return nil
}
