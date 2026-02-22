package credit_scoring

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"cosmossdk.io/log"

	demotypes "github.com/aethelred/aethelred/x/demo/types"
)

// DemoAPI provides HTTP endpoints for the credit scoring demo
type DemoAPI struct {
	logger       log.Logger
	pipeline     *CreditScoringPipeline
	processor    *ApplicationProcessor
	orchestrator *VerificationOrchestrator
	mux          *http.ServeMux
}

// NewDemoAPI creates a new demo API
func NewDemoAPI(
	logger log.Logger,
	pipeline *CreditScoringPipeline,
	processor *ApplicationProcessor,
	orchestrator *VerificationOrchestrator,
) *DemoAPI {
	api := &DemoAPI{
		logger:       logger,
		pipeline:     pipeline,
		processor:    processor,
		orchestrator: orchestrator,
		mux:          http.NewServeMux(),
	}

	api.registerRoutes()
	return api
}

// registerRoutes registers all API routes
func (api *DemoAPI) registerRoutes() {
	// Models
	api.mux.HandleFunc("/api/v1/models", api.handleModels)
	api.mux.HandleFunc("/api/v1/models/", api.handleModelByID)

	// Applications
	api.mux.HandleFunc("/api/v1/applications", api.handleApplications)
	api.mux.HandleFunc("/api/v1/applications/", api.handleApplicationByID)

	// Scoring
	api.mux.HandleFunc("/api/v1/score", api.handleScore)
	api.mux.HandleFunc("/api/v1/score/verified", api.handleVerifiedScore)
	api.mux.HandleFunc("/api/v1/score/batch", api.handleBatchScore)

	// Results
	api.mux.HandleFunc("/api/v1/results/", api.handleResultByID)

	// Verification
	api.mux.HandleFunc("/api/v1/verify/", api.handleVerify)
	api.mux.HandleFunc("/api/v1/seals/", api.handleSealByID)

	// Metrics
	api.mux.HandleFunc("/api/v1/metrics", api.handleMetrics)

	// Health
	api.mux.HandleFunc("/api/v1/health", api.handleHealth)

	// Demo scenarios
	api.mux.HandleFunc("/api/v1/demo/scenarios", api.handleDemoScenarios)
	api.mux.HandleFunc("/api/v1/demo/run", api.handleDemoRun)
}

// ServeHTTP implements http.Handler
func (api *DemoAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	api.mux.ServeHTTP(w, r)
}

// Handler returns the HTTP handler
func (api *DemoAPI) Handler() http.Handler {
	return api.mux
}

// Response helpers

func jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func errorResponse(w http.ResponseWriter, message string, status int) {
	jsonResponse(w, map[string]string{"error": message}, status)
}

// Handlers

func (api *DemoAPI) handleModels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		models := api.pipeline.ListModels()
		jsonResponse(w, map[string]interface{}{
			"models": models,
			"count":  len(models),
		}, http.StatusOK)

	case http.MethodPost:
		var model demotypes.CreditScoringModel
		if err := json.NewDecoder(r.Body).Decode(&model); err != nil {
			errorResponse(w, "Invalid model data", http.StatusBadRequest)
			return
		}

		if err := api.pipeline.RegisterModel(&model); err != nil {
			errorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		jsonResponse(w, model, http.StatusCreated)

	default:
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *DemoAPI) handleModelByID(w http.ResponseWriter, r *http.Request) {
	modelID := r.URL.Path[len("/api/v1/models/"):]
	if modelID == "" {
		errorResponse(w, "Model ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		model, err := api.pipeline.GetModel(modelID)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonResponse(w, model, http.StatusOK)

	default:
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *DemoAPI) handleApplications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		apps := api.pipeline.ListApplications()
		jsonResponse(w, map[string]interface{}{
			"applications": apps,
			"count":        len(apps),
		}, http.StatusOK)

	case http.MethodPost:
		var req ApplicationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			errorResponse(w, "Invalid application data", http.StatusBadRequest)
			return
		}

		app := demotypes.NewLoanApplication(
			req.ApplicantID,
			req.LoanType,
			req.LoanAmount,
			req.LoanTerm,
			req.Features,
			req.ModelID,
			req.Submitter,
		)

		ctx := context.Background()
		app, err := api.pipeline.SubmitApplication(ctx, app)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		jsonResponse(w, app, http.StatusCreated)

	default:
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *DemoAPI) handleApplicationByID(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Path[len("/api/v1/applications/"):]
	if appID == "" {
		errorResponse(w, "Application ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		app, err := api.pipeline.GetApplication(appID)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonResponse(w, app, http.StatusOK)

	default:
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *DemoAPI) handleScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ApplicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	app := demotypes.NewLoanApplication(
		req.ApplicantID,
		req.LoanType,
		req.LoanAmount,
		req.LoanTerm,
		req.Features,
		req.ModelID,
		req.Submitter,
	)

	ctx := context.Background()

	// Process synchronously
	result, err := api.processor.ProcessSync(ctx, app)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, ScoreResponse{
		ApplicationID: app.ApplicationID,
		Result:        result,
		Application:   app,
	}, http.StatusOK)
}

func (api *DemoAPI) handleVerifiedScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ApplicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	app := demotypes.NewLoanApplication(
		req.ApplicantID,
		req.LoanType,
		req.LoanAmount,
		req.LoanTerm,
		req.Features,
		req.ModelID,
		req.Submitter,
	)

	ctx := context.Background()

	// Process with verification
	verifiedResult, err := api.orchestrator.ProcessWithVerification(ctx, app)
	if err != nil {
		errorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Simulate consensus verification
	consensusResult, err := api.orchestrator.SimulateConsensusVerification(ctx, verifiedResult.SealID)
	if err != nil {
		api.logger.Warn("Consensus verification failed", "error", err)
	}

	jsonResponse(w, VerifiedScoreResponse{
		ApplicationID:   app.ApplicationID,
		Result:          verifiedResult.Result,
		Application:     verifiedResult.Application,
		SealID:          verifiedResult.SealID,
		Verified:        consensusResult != nil && consensusResult.Verified,
		ConsensusResult: consensusResult,
		ProcessingMs:    verifiedResult.TotalProcessingMs,
	}, http.StatusOK)
}

func (api *DemoAPI) handleBatchScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BatchScoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	results := make([]ScoreResponse, 0, len(req.Applications))

	for _, appReq := range req.Applications {
		app := demotypes.NewLoanApplication(
			appReq.ApplicantID,
			appReq.LoanType,
			appReq.LoanAmount,
			appReq.LoanTerm,
			appReq.Features,
			appReq.ModelID,
			appReq.Submitter,
		)

		result, err := api.processor.ProcessSync(ctx, app)
		if err != nil {
			api.logger.Warn("Batch scoring failed for application",
				"applicant_id", appReq.ApplicantID,
				"error", err,
			)
			continue
		}

		results = append(results, ScoreResponse{
			ApplicationID: app.ApplicationID,
			Result:        result,
			Application:   app,
		})
	}

	jsonResponse(w, BatchScoreResponse{
		Results: results,
		Count:   len(results),
	}, http.StatusOK)
}

func (api *DemoAPI) handleResultByID(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Path[len("/api/v1/results/"):]
	if appID == "" {
		errorResponse(w, "Application ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		result, err := api.pipeline.GetResult(appID)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonResponse(w, result, http.StatusOK)

	default:
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *DemoAPI) handleVerify(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Path[len("/api/v1/verify/"):]
	if appID == "" {
		errorResponse(w, "Application ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		sealID, err := api.orchestrator.GetSealID(appID)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusNotFound)
			return
		}

		consensusResult, err := api.orchestrator.SimulateConsensusVerification(context.Background(), sealID)
		if err != nil {
			errorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonResponse(w, consensusResult, http.StatusOK)

	default:
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *DemoAPI) handleSealByID(w http.ResponseWriter, r *http.Request) {
	sealID := r.URL.Path[len("/api/v1/seals/"):]
	if sealID == "" {
		errorResponse(w, "Seal ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// In production, this would fetch from the blockchain
		jsonResponse(w, map[string]interface{}{
			"seal_id": sealID,
			"status":  "active",
			"message": "Seal verification would query the blockchain",
		}, http.StatusOK)

	default:
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (api *DemoAPI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics := api.pipeline.GetMetrics()
	jsonResponse(w, map[string]interface{}{
		"pipeline": metrics,
		"queue": map[string]interface{}{
			"length":  api.processor.GetQueueLength(),
			"pending": api.processor.GetPendingCount(),
		},
	}, http.StatusOK)
}

func (api *DemoAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	}, http.StatusOK)
}

func (api *DemoAPI) handleDemoScenarios(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scenarios := GetDemoScenarios()
	jsonResponse(w, map[string]interface{}{
		"scenarios": scenarios,
		"count":     len(scenarios),
	}, http.StatusOK)
}

func (api *DemoAPI) handleDemoRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DemoRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	results := make([]DemoScenarioResult, 0)

	scenarios := GetDemoScenarios()
	for _, scenario := range scenarios {
		if req.ScenarioID != "" && scenario.ID != req.ScenarioID {
			continue
		}

		app := demotypes.NewLoanApplication(
			scenario.ApplicantID,
			scenario.LoanType,
			scenario.LoanAmount,
			scenario.LoanTerm,
			scenario.Features,
			"credit-score-v1",
			"demo-api",
		)

		var result *demotypes.CreditScoringResult
		var sealID string
		var consensusResult *ConsensusVerificationResult

		if req.WithVerification {
			verifiedResult, err := api.orchestrator.ProcessWithVerification(ctx, app)
			if err != nil {
				api.logger.Warn("Demo scenario failed", "scenario", scenario.ID, "error", err)
				continue
			}
			result = verifiedResult.Result
			sealID = verifiedResult.SealID
			consensusResult, _ = api.orchestrator.SimulateConsensusVerification(ctx, sealID)
		} else {
			var err error
			result, err = api.processor.ProcessSync(ctx, app)
			if err != nil {
				api.logger.Warn("Demo scenario failed", "scenario", scenario.ID, "error", err)
				continue
			}
		}

		results = append(results, DemoScenarioResult{
			Scenario:        scenario,
			ApplicationID:   app.ApplicationID,
			Result:          result,
			SealID:          sealID,
			ConsensusResult: consensusResult,
		})
	}

	jsonResponse(w, map[string]interface{}{
		"results":           results,
		"count":             len(results),
		"with_verification": req.WithVerification,
	}, http.StatusOK)
}

// Request/Response types

// ApplicationRequest is the request for submitting an application
type ApplicationRequest struct {
	ApplicantID string                    `json:"applicant_id"`
	LoanType    string                    `json:"loan_type"`
	LoanAmount  float64                   `json:"loan_amount"`
	LoanTerm    int                       `json:"loan_term"`
	Features    *demotypes.CreditFeatures `json:"features"`
	ModelID     string                    `json:"model_id,omitempty"`
	Submitter   string                    `json:"submitter,omitempty"`
}

// ScoreResponse is the response for a scoring request
type ScoreResponse struct {
	ApplicationID string                         `json:"application_id"`
	Result        *demotypes.CreditScoringResult `json:"result"`
	Application   *demotypes.LoanApplication     `json:"application"`
}

// VerifiedScoreResponse is the response for a verified scoring request
type VerifiedScoreResponse struct {
	ApplicationID   string                         `json:"application_id"`
	Result          *demotypes.CreditScoringResult `json:"result"`
	Application     *demotypes.LoanApplication     `json:"application"`
	SealID          string                         `json:"seal_id"`
	Verified        bool                           `json:"verified"`
	ConsensusResult *ConsensusVerificationResult   `json:"consensus_result,omitempty"`
	ProcessingMs    int64                          `json:"processing_ms"`
}

// BatchScoreRequest is the request for batch scoring
type BatchScoreRequest struct {
	Applications []ApplicationRequest `json:"applications"`
}

// BatchScoreResponse is the response for batch scoring
type BatchScoreResponse struct {
	Results []ScoreResponse `json:"results"`
	Count   int             `json:"count"`
}

// DemoRunRequest is the request for running demo scenarios
type DemoRunRequest struct {
	ScenarioID       string `json:"scenario_id,omitempty"`
	WithVerification bool   `json:"with_verification"`
}

// DemoScenarioResult contains the result of running a demo scenario
type DemoScenarioResult struct {
	Scenario        *DemoScenario                  `json:"scenario"`
	ApplicationID   string                         `json:"application_id"`
	Result          *demotypes.CreditScoringResult `json:"result"`
	SealID          string                         `json:"seal_id,omitempty"`
	ConsensusResult *ConsensusVerificationResult   `json:"consensus_result,omitempty"`
}

// StartServer starts the demo API server
func (api *DemoAPI) StartServer(addr string) error {
	api.logger.Info("Starting demo API server", "address", addr)

	server := &http.Server{
		Addr:         addr,
		Handler:      api,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server.ListenAndServe()
}
