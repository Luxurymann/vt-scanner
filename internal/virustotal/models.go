package virustotal

type ReportResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			LastAnalysisResults map[string]EngineResult `json:"last_analysis_results"`
			Size                int64                   `json:"size"`
			MeaningfulName      string                  `json:"meaningful_name"`
		} `json:"attributes"`
	} `json:"data"`
	Error *APIError `json:"error,omitempty"`
}

type EngineResult struct {
	Category   string `json:"category"`
	EngineName string `json:"engine_name"`
	Result     string `json:"result"`
}

type APIError struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

type UploadURLResponse struct {
	Data string `json:"data"`
}

type AnalysisResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Status string `json:"status"`
			Stats  struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
				Timeout    int `json:"timeout"`
			} `json:"stats"`
			Results map[string]EngineResult `json:"results"`
		} `json:"attributes"`
	} `json:"data"`
	Error *APIError `json:"error,omitempty"`
}

type UploadResponse struct {
	Data struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
	Error *APIError `json:"error,omitempty"`
}
