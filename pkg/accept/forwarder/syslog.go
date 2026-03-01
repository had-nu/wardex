// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package forwarder

import (
	"encoding/json"
	"log/syslog"
	"strings"

	"github.com/had-nu/wardex/pkg/model"
)

type SyslogBackend struct {
	Address  string
	Protocol string
	Facility syslog.Priority
	writer   *syslog.Writer
}

func parseFacility(fac string) syslog.Priority {
	switch strings.ToLower(fac) {
	case "kern":
		return syslog.LOG_KERN
	case "user":
		return syslog.LOG_USER
	case "mail":
		return syslog.LOG_MAIL
	case "daemon":
		return syslog.LOG_DAEMON
	case "auth":
		return syslog.LOG_AUTH
	case "syslog":
		return syslog.LOG_SYSLOG
	case "lpr":
		return syslog.LOG_LPR
	case "news":
		return syslog.LOG_NEWS
	case "uucp":
		return syslog.LOG_UUCP
	case "cron":
		return syslog.LOG_CRON
	case "authpriv":
		return syslog.LOG_AUTHPRIV
	case "ftp":
		return syslog.LOG_FTP
	case "local0":
		return syslog.LOG_LOCAL0
	case "local1":
		return syslog.LOG_LOCAL1
	case "local2":
		return syslog.LOG_LOCAL2
	case "local3":
		return syslog.LOG_LOCAL3
	case "local4":
		return syslog.LOG_LOCAL4
	case "local5":
		return syslog.LOG_LOCAL5
	case "local6":
		return syslog.LOG_LOCAL6
	case "local7":
		return syslog.LOG_LOCAL7
	}
	return syslog.LOG_LOCAL0
}

func NewSyslogBackend(address, protocol, facility string) (*SyslogBackend, error) {
	fac := parseFacility(facility)
	writer, err := syslog.Dial(protocol, address, fac|syslog.LOG_INFO, "wardex-accept")
	if err != nil {
		return nil, err
	}

	return &SyslogBackend{
		Address:  address,
		Protocol: protocol,
		Facility: fac,
		writer:   writer,
	}, nil
}

func (b *SyslogBackend) Name() string {
	return "syslog"
}

func (b *SyslogBackend) Send(entry model.AuditEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return b.writer.Info(string(payload))
}
