package virustotal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

const baseURL = "https://www.virustotal.com/api/v3"

type Client struct {
	apiKey     string
	httpClient *http.Client
}

func NewClient(apiKey string) *Client {
	return &Client{
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

func (c *Client) doRequest(req *http.Request) ([]byte, error) {
	req.Header.Add("x-apikey", c.apiKey)
	req.Header.Add("accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 && resp.StatusCode != 404 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetReportByHash checks if the file is already analyzed by its SHA256 hash.
// Returns nil, nil if the report is not found (404).
func (c *Client) GetReportByHash(hash string) (*ReportResponse, error) {
	url := fmt.Sprintf("%s/files/%s", baseURL, hash)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("x-apikey", c.apiKey)
	req.Header.Add("accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 404 {
		return nil, nil // Not found, needs upload
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var report ReportResponse
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, err
	}

	return &report, nil
}

// GetUploadURL requests a special URL for uploading files between 32MB and 200MB.
func (c *Client) GetUploadURL() (string, error) {
	url := fmt.Sprintf("%s/files/upload_url", baseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	body, err := c.doRequest(req)
	if err != nil {
		return "", err
	}

	var uploadURLResp UploadURLResponse
	if err := json.Unmarshal(body, &uploadURLResp); err != nil {
		return "", err
	}

	if uploadURLResp.Data == "" {
		return "", errors.New("empty upload url returned")
	}

	return uploadURLResp.Data, nil
}

// UploadFile uploads a file to VirusTotal.
// If uploadURL is empty, it uses the standard endpoint (for files < 32MB).
func (c *Client) UploadFile(filePath string, uploadURL string) (*UploadResponse, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Prepare multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return nil, err
	}
	writer.Close()

	targetURL := uploadURL
	if targetURL == "" {
		targetURL = fmt.Sprintf("%s/files", baseURL)
	}

	req, err := http.NewRequest("POST", targetURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	respBody, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var uploadResp UploadResponse
	if err := json.Unmarshal(respBody, &uploadResp); err != nil {
		return nil, err
	}

	if uploadResp.Error != nil {
		return nil, fmt.Errorf("upload error: %s", uploadResp.Error.Message)
	}

	return &uploadResp, nil
}

// GetAnalysisStatus gets the current status of an analysis using its ID.
func (c *Client) GetAnalysisStatus(id string) (*AnalysisResponse, error) {
	url := fmt.Sprintf("%s/analyses/%s", baseURL, id)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var analysisResp AnalysisResponse
	if err := json.Unmarshal(body, &analysisResp); err != nil {
		return nil, err
	}

	return &analysisResp, nil
}
