// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package duration

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseExtended parses a duration string with support for day suffix "d".
// It extends Go's time.ParseDuration with "d" → n * 24h conversion.
// Supported: "30d", "3d", "72h", "1h30m", "500ms", etc.
// Rejects: negative days, empty string, non-numeric prefix before "d".
func ParseExtended(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	if strings.HasSuffix(s, "d") {
		dayStr := strings.TrimSuffix(s, "d")
		n, err := strconv.Atoi(dayStr)
		if err != nil {
			return 0, fmt.Errorf("invalid day duration %q: %w", s, err)
		}
		if n < 0 {
			return 0, fmt.Errorf("negative duration not allowed: %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
}
