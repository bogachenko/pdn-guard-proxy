package pdn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

var ErrNatashaUnavailable = errors.New("natasha pdd analyzer unavailable")

type NatashaClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

type natashaAnalyzeRequest struct {
	Text string `json:"text"`
}

type NatashaAnalyzeResponse struct {
	HasEntities bool            `json:"has_entities"`
	Entities    []NatashaEntity `json:"entities"`
}

type NatashaEntity struct {
	Type  string `json:"type"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

func NewNatashaClient(baseURL string, timeout time.Duration) *NatashaClient {
	return &NatashaClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *NatashaClient) Analyze(ctx context.Context, text string) (NatashaAnalyzeResponse, error) {
	payload, err := json.Marshal(natashaAnalyzeRequest{Text: text})
	if err != nil {
		return NatashaAnalyzeResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/analyze", bytes.NewReader(payload))
	if err != nil {
		return NatashaAnalyzeResponse{}, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return NatashaAnalyzeResponse{}, ErrNatashaUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NatashaAnalyzeResponse{}, ErrNatashaUnavailable
	}

	var result NatashaAnalyzeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return NatashaAnalyzeResponse{}, err
	}

	return result, nil
}
