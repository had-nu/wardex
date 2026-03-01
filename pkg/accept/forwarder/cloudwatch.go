// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

//go:build cloudwatch

package forwarder

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/had-nu/wardex/pkg/model"
)

type CloudWatchBackend struct {
	LogGroup  string
	LogStream string
	client    *cloudwatchlogs.Client
}

func NewCloudWatchBackend(region, logGroup, logStream string) (*CloudWatchBackend, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading aws config: %w", err)
	}

	client := cloudwatchlogs.NewFromConfig(cfg)
	return &CloudWatchBackend{
		LogGroup:  logGroup,
		LogStream: logStream,
		client:    client,
	}, nil
}

func (b *CloudWatchBackend) Name() string {
	return "cloudwatch"
}

func (b *CloudWatchBackend) Send(entry model.AuditEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	input := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  aws.String(b.LogGroup),
		LogStreamName: aws.String(b.LogStream),
		LogEvents: []types.InputLogEvent{
			{
				Message:   aws.String(string(payload)),
				Timestamp: aws.Int64(timestamp),
			},
		},
	}

	_, err = b.client.PutLogEvents(context.TODO(), input)
	return err
}
