package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Luxurymann/vt-scanner/internal/archive"
	"github.com/Luxurymann/vt-scanner/internal/virustotal"
)

const (
	Size32MB  = 32 * 1024 * 1024
	Size200MB = 200 * 1024 * 1024
	RateLimit = 15500 * time.Millisecond // 15.5s to strictly stay under 4 req/min
)

var ignoredExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".ico": true, ".webp": true, ".bmp": true, ".svg": true,
	".txt": true, ".json": true, ".xml": true, ".ini": true,
	".cfg": true, ".md": true, ".csv": true, ".pdb": true,
	".mp3": true, ".wav": true, ".ogg": true, ".mp4": true,
	".avi": true, ".webm": true,
	// Additional safe game/data formats
	".vdf": true, ".url": true, ".pdf": true, ".sub": true,
	".xnb": true, ".otf": true, ".ttf": true,
}

type ScanResult struct {
	FilePath  string `json:"file_path"`
	Hash      string `json:"hash"`
	Status    string `json:"status"`
	Malicious int    `json:"malicious"`
	Total     int    `json:"total"`
	Message   string `json:"message,omitempty"`
}

type ScanTask struct {
	FilePath  string
	Hash      string
	Size      int64
	IsArchive bool
}

type Scanner struct {
	vtClient    *virustotal.Client
	uploadNew   bool
	
	results     []ScanResult
	mu          sync.Mutex

	taskQueue   chan *ScanTask
	uploadQueue chan *ScanTask
	
	rateLimiter *time.Ticker
	wg          sync.WaitGroup

	// Stats
	pendingHashes int
	pendingUploads int
	statsMu       sync.Mutex
}

func NewScanner(apiKey string, uploadNew bool) *Scanner {
	return &Scanner{
		vtClient:    virustotal.NewClient(apiKey),
		uploadNew:   uploadNew,
		results:     make([]ScanResult, 0),
		taskQueue:   make(chan *ScanTask, 100000),
		uploadQueue: make(chan *ScanTask, 10000),
		rateLimiter: time.NewTicker(RateLimit),
	}
}

func (s *Scanner) StartWorkers(count int) {
	// Start status ticker
	go s.statusTicker()

	// Start workers
	for i := 0; i < count; i++ {
		s.wg.Add(1)
		go s.worker()
	}
}

func (s *Scanner) Wait() {
	close(s.taskQueue)
	s.wg.Wait()
	s.rateLimiter.Stop()
}

func (s *Scanner) statusTicker() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.statsMu.Lock()
		hashes := s.pendingHashes
		uploads := s.pendingUploads
		s.statsMu.Unlock()

		if hashes == 0 && uploads == 0 {
			continue // Nothing pending
		}

		totalApiCalls := hashes + (uploads * 2) // roughly 2 calls per upload (upload + poll)
		etaSec := float64(totalApiCalls) * RateLimit.Seconds()
		eta := time.Duration(etaSec) * time.Second

		fmt.Printf("[STATUS] Waiting for hash check: %d | Waiting for upload: %d | ETA: %v\n", hashes, uploads, eta)
	}
}

func (s *Scanner) worker() {
	defer s.wg.Done()

	for task := range s.taskQueue {
		// Wait for rate limit
		<-s.rateLimiter.C

		report, err := s.vtClient.GetReportByHash(task.Hash)
		if err != nil {
			s.appendError(task.FilePath, task.Hash, fmt.Sprintf("error checking hash on VT: %v", err))
			s.decPendingHashes()
			continue
		}

		if report != nil {
			s.processReport(task.FilePath, task.Hash, report)
			s.decPendingHashes()
			continue
		}

		// Hash not found
		s.decPendingHashes()
		
		if s.uploadNew && !task.IsArchive {
			// Schedule for upload if it's a real disk file
			s.incPendingUploads()
			s.doUpload(task)
		} else {
			// Skip upload
			msg := "Not found on VT (Skipped upload)"
			if task.IsArchive {
				msg = "Not found on VT (Archived files are not uploaded automatically)"
			}
			s.appendResult(task.FilePath, task.Hash, "NOT_FOUND", 0, 0, msg)
		}
	}
}

func (s *Scanner) doUpload(task *ScanTask) {
	// Wait for rate limit to request upload URL or directly upload
	<-s.rateLimiter.C

	if task.Size > Size200MB {
		s.appendError(task.FilePath, task.Hash, "File larger than 200MB (VT limit)")
		s.decPendingUploads()
		return
	}

	var uploadURL string
	var err error
	if task.Size >= Size32MB {
		uploadURL, err = s.vtClient.GetUploadURL()
		if err != nil {
			s.appendError(task.FilePath, task.Hash, fmt.Sprintf("failed to get upload URL: %v", err))
			s.decPendingUploads()
			return
		}
		// GetUploadURL took a rate limit token. We need another one for the actual upload POST
		<-s.rateLimiter.C
	}

	uploadResp, err := s.vtClient.UploadFile(task.FilePath, uploadURL)
	if err != nil {
		s.appendError(task.FilePath, task.Hash, fmt.Sprintf("upload failed: %v", err))
		s.decPendingUploads()
		return
	}

	analysisID := uploadResp.Data.ID
	
	// Poll for results
	for {
		<-s.rateLimiter.C
		
		analysis, err := s.vtClient.GetAnalysisStatus(analysisID)
		if err != nil {
			s.appendError(task.FilePath, task.Hash, fmt.Sprintf("failed to get analysis status: %v", err))
			s.decPendingUploads()
			return
		}

		status := analysis.Data.Attributes.Status
		if status == "queued" || status == "in-progress" {
			continue // Need to poll again
		}

		if status == "completed" {
			s.processAnalysis(task.FilePath, task.Hash, analysis)
			s.decPendingUploads()
			return
		}

		s.appendError(task.FilePath, task.Hash, fmt.Sprintf("unknown analysis status: %s", status))
		s.decPendingUploads()
		return
	}
}

func (s *Scanner) QueueFile(filePath, password string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return filepath.Walk(filePath, func(path string, d os.FileInfo, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			s.processLocalFile(path, password, d.Size())
			return nil
		})
	}

	s.processLocalFile(filePath, password, info.Size())
	return nil
}

func (s *Scanner) processLocalFile(filePath, password string, size int64) {
	if isIgnored(filePath) {
		return
	}

	if isArchive(filePath) {
		fmt.Printf("[*] Streaming archive into memory: %s\n", filePath)
		err := archive.Stream(filePath, password, func(name string, uncompressedSize int64, reader io.Reader) error {
			if isIgnored(name) {
				return nil
			}
			
			hash := sha256.New()
			if _, err := io.Copy(hash, reader); err != nil {
				return err
			}
			hashStr := fmt.Sprintf("%x", hash.Sum(nil))
			
			virtualPath := fmt.Sprintf("%s/%s", filepath.Base(filePath), name)
			
			s.incPendingHashes()
			s.taskQueue <- &ScanTask{
				FilePath:  virtualPath,
				Hash:      hashStr,
				Size:      uncompressedSize,
				IsArchive: true,
			}
			return nil
		})
		
		if err != nil {
			fmt.Printf("[!] Error streaming archive %s: %v\n", filePath, err)
		}
		return
	}

	// Regular file
	hash, err := calculateHash(filePath)
	if err != nil {
		fmt.Printf("[!] Error calculating hash for %s: %v\n", filePath, err)
		return
	}

	s.incPendingHashes()
	s.taskQueue <- &ScanTask{
		FilePath:  filePath,
		Hash:      hash,
		Size:      size,
		IsArchive: false,
	}
}

func (s *Scanner) incPendingHashes() {
	s.statsMu.Lock()
	s.pendingHashes++
	s.statsMu.Unlock()
}
func (s *Scanner) decPendingHashes() {
	s.statsMu.Lock()
	s.pendingHashes--
	s.statsMu.Unlock()
}
func (s *Scanner) incPendingUploads() {
	s.statsMu.Lock()
	s.pendingUploads++
	s.statsMu.Unlock()
}
func (s *Scanner) decPendingUploads() {
	s.statsMu.Lock()
	s.pendingUploads--
	s.statsMu.Unlock()
}

func (s *Scanner) processReport(filePath, hash string, report *virustotal.ReportResponse) {
	stats := report.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless + stats.Timeout
	s.addResult(filePath, hash, stats.Malicious, stats.Suspicious, total)
}

func (s *Scanner) processAnalysis(filePath, hash string, analysis *virustotal.AnalysisResponse) {
	stats := analysis.Data.Attributes.Stats
	total := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless + stats.Timeout
	s.addResult(filePath, hash, stats.Malicious, stats.Suspicious, total)
}

func (s *Scanner) addResult(filePath, hash string, malicious, suspicious, total int) {
	status := "SAFE"
	if malicious > 0 {
		status = "DANGER"
		fmt.Printf("[!] DANGER: %s (%d/%d engines detected as malicious)\n", filepath.Base(filePath), malicious, total)
	} else if suspicious > 0 {
		status = "SUSPICIOUS"
		fmt.Printf("[?] SUSPICIOUS: %s (%d/%d engines detected as suspicious)\n", filepath.Base(filePath), suspicious, total)
	} else {
		fmt.Printf("[+] SAFE: %s (0/%d engines detected threats)\n", filepath.Base(filePath), total)
	}

	s.appendResult(filePath, hash, status, malicious, total, "")
}

func (s *Scanner) appendResult(filePath, hash, status string, malicious, total int, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, ScanResult{
		FilePath:  filePath,
		Hash:      hash,
		Status:    status,
		Malicious: malicious,
		Total:     total,
		Message:   message,
	})
}

func (s *Scanner) appendError(filePath, hash, message string) {
	s.appendResult(filePath, hash, "ERROR", 0, 0, message)
	fmt.Printf("[!] ERROR on %s: %s\n", filepath.Base(filePath), message)
}

func (s *Scanner) SaveFinalReport(reportPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if len(s.results) == 0 {
		fmt.Println("[i] No files were scanned. Report is empty.")
		return
	}

	bytes, err := json.MarshalIndent(s.results, "", "  ")
	if err != nil {
		fmt.Printf("[!] Error creating final report: %v\n", err)
		return
	}

	if err := os.WriteFile(reportPath, bytes, 0644); err != nil {
		fmt.Printf("[!] Error writing final report to %s: %v\n", reportPath, err)
		return
	}

	fmt.Printf("[i] =======================================\n")
	fmt.Printf("[i] Scan finished! Detailed report saved to: %s\n", reportPath)
}

func calculateHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func isArchive(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".zip" || ext == ".tar" || ext == ".rar" || ext == ".iso" || (ext == ".gz" && strings.HasSuffix(strings.ToLower(filePath), ".tar.gz"))
}

func isIgnored(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	_, ignored := ignoredExtensions[ext]
	return ignored
}
