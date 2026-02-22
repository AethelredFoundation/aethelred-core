package credit_scoring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"cosmossdk.io/log"

	demotypes "github.com/aethelred/aethelred/x/demo/types"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

// ApplicationProcessor handles the full lifecycle of loan applications
type ApplicationProcessor struct {
	logger   log.Logger
	pipeline *CreditScoringPipeline
	config   ProcessorConfig

	// Processing queue
	queue     chan *ProcessingTask
	workers   int
	wg        sync.WaitGroup
	isRunning bool
	stopCh    chan struct{}

	// Callbacks
	onComplete func(*demotypes.LoanApplication, *demotypes.CreditScoringResult)
	onError    func(*demotypes.LoanApplication, error)

	// Job tracking
	jobs     map[string]*ProcessingTask
	jobMutex sync.RWMutex
}

// ProcessorConfig contains configuration for the processor
type ProcessorConfig struct {
	// WorkerCount number of concurrent workers
	WorkerCount int

	// QueueSize max pending tasks
	QueueSize int

	// ProcessingTimeout per application
	ProcessingTimeout time.Duration

	// RetryCount for failed processing
	RetryCount int

	// RetryDelay between retries
	RetryDelay time.Duration

	// EnableVerification enables blockchain verification
	EnableVerification bool
}

// DefaultProcessorConfig returns default configuration
func DefaultProcessorConfig() ProcessorConfig {
	return ProcessorConfig{
		WorkerCount:        4,
		QueueSize:          100,
		ProcessingTimeout:  60 * time.Second,
		RetryCount:         3,
		RetryDelay:         time.Second,
		EnableVerification: true,
	}
}

// ProcessingTask represents a processing task
type ProcessingTask struct {
	// Application to process
	Application *demotypes.LoanApplication

	// Job for consensus
	Job *pouwtypes.ComputeJob

	// Attempt number
	Attempt int

	// CreatedAt when task was created
	CreatedAt time.Time

	// StartedAt when processing started
	StartedAt *time.Time

	// CompletedAt when processing completed
	CompletedAt *time.Time

	// Error if processing failed
	Error error

	// Result of processing
	Result *demotypes.CreditScoringResult
}

// NewApplicationProcessor creates a new processor
func NewApplicationProcessor(logger log.Logger, pipeline *CreditScoringPipeline, config ProcessorConfig) *ApplicationProcessor {
	return &ApplicationProcessor{
		logger:   logger,
		pipeline: pipeline,
		config:   config,
		queue:    make(chan *ProcessingTask, config.QueueSize),
		workers:  config.WorkerCount,
		stopCh:   make(chan struct{}),
		jobs:     make(map[string]*ProcessingTask),
	}
}

// Start starts the processor workers
func (p *ApplicationProcessor) Start() {
	if p.isRunning {
		return
	}

	p.isRunning = true
	p.stopCh = make(chan struct{})

	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}

	p.logger.Info("Application processor started",
		"workers", p.workers,
		"queue_size", p.config.QueueSize,
	)
}

// Stop stops the processor
func (p *ApplicationProcessor) Stop() {
	if !p.isRunning {
		return
	}

	close(p.stopCh)
	p.wg.Wait()
	p.isRunning = false

	p.logger.Info("Application processor stopped")
}

// SetOnComplete sets the completion callback
func (p *ApplicationProcessor) SetOnComplete(callback func(*demotypes.LoanApplication, *demotypes.CreditScoringResult)) {
	p.onComplete = callback
}

// SetOnError sets the error callback
func (p *ApplicationProcessor) SetOnError(callback func(*demotypes.LoanApplication, error)) {
	p.onError = callback
}

// Submit submits an application for processing
func (p *ApplicationProcessor) Submit(ctx context.Context, app *demotypes.LoanApplication) (*ProcessingTask, error) {
	// Submit to pipeline first
	app, err := p.pipeline.SubmitApplication(ctx, app)
	if err != nil {
		return nil, fmt.Errorf("failed to submit application: %w", err)
	}

	// Create compute job
	job, err := p.pipeline.CreateComputeJob(app)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute job: %w", err)
	}

	// Create processing task
	task := &ProcessingTask{
		Application: app,
		Job:         job,
		Attempt:     0,
		CreatedAt:   time.Now().UTC(),
	}

	// Track task
	p.jobMutex.Lock()
	p.jobs[app.ApplicationID] = task
	p.jobMutex.Unlock()

	// Queue for processing
	select {
	case p.queue <- task:
		p.logger.Debug("Application queued for processing",
			"application_id", app.ApplicationID,
		)
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("processing queue is full")
	}

	return task, nil
}

// worker processes tasks from the queue
func (p *ApplicationProcessor) worker(id int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.stopCh:
			return
		case task := <-p.queue:
			p.processTask(task)
		}
	}
}

// processTask processes a single task
func (p *ApplicationProcessor) processTask(task *ProcessingTask) {
	now := time.Now().UTC()
	task.StartedAt = &now
	task.Attempt++

	ctx, cancel := context.WithTimeout(context.Background(), p.config.ProcessingTimeout)
	defer cancel()

	p.logger.Debug("Processing application",
		"application_id", task.Application.ApplicationID,
		"attempt", task.Attempt,
	)

	// Process the application
	result, err := p.pipeline.ProcessApplication(ctx, task.Application.ApplicationID)
	if err != nil {
		task.Error = err

		// Retry if applicable
		if task.Attempt < p.config.RetryCount {
			p.logger.Warn("Application processing failed, retrying",
				"application_id", task.Application.ApplicationID,
				"attempt", task.Attempt,
				"error", err,
			)

			time.Sleep(p.config.RetryDelay)
			p.queue <- task
			return
		}

		// Final failure
		p.logger.Error("Application processing failed",
			"application_id", task.Application.ApplicationID,
			"error", err,
		)

		if p.onError != nil {
			p.onError(task.Application, err)
		}
		return
	}

	// Success
	completed := time.Now().UTC()
	task.CompletedAt = &completed
	task.Result = result

	p.logger.Info("Application processed successfully",
		"application_id", task.Application.ApplicationID,
		"score", result.Score,
		"decision", result.Decision,
	)

	if p.onComplete != nil {
		p.onComplete(task.Application, result)
	}
}

// GetTask returns a task by application ID
func (p *ApplicationProcessor) GetTask(applicationID string) (*ProcessingTask, error) {
	p.jobMutex.RLock()
	defer p.jobMutex.RUnlock()

	task, ok := p.jobs[applicationID]
	if !ok {
		return nil, fmt.Errorf("task not found: %s", applicationID)
	}

	return task, nil
}

// ProcessSync processes an application synchronously (blocking)
func (p *ApplicationProcessor) ProcessSync(ctx context.Context, app *demotypes.LoanApplication) (*demotypes.CreditScoringResult, error) {
	// Submit to pipeline
	app, err := p.pipeline.SubmitApplication(ctx, app)
	if err != nil {
		return nil, err
	}

	// Process directly
	return p.pipeline.ProcessApplication(ctx, app.ApplicationID)
}

// BatchSubmit submits multiple applications
func (p *ApplicationProcessor) BatchSubmit(ctx context.Context, apps []*demotypes.LoanApplication) ([]*ProcessingTask, error) {
	tasks := make([]*ProcessingTask, 0, len(apps))

	for _, app := range apps {
		task, err := p.Submit(ctx, app)
		if err != nil {
			p.logger.Warn("Failed to submit application in batch",
				"application_id", app.ApplicationID,
				"error", err,
			)
			continue
		}
		tasks = append(tasks, task)
	}

	return tasks, nil
}

// WaitForCompletion waits for a task to complete
func (p *ApplicationProcessor) WaitForCompletion(ctx context.Context, applicationID string) (*demotypes.CreditScoringResult, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			task, err := p.GetTask(applicationID)
			if err != nil {
				return nil, err
			}

			if task.CompletedAt != nil {
				return task.Result, nil
			}

			if task.Error != nil {
				return nil, task.Error
			}
		}
	}
}

// GetQueueLength returns the current queue length
func (p *ApplicationProcessor) GetQueueLength() int {
	return len(p.queue)
}

// GetPendingCount returns the number of pending tasks
func (p *ApplicationProcessor) GetPendingCount() int {
	p.jobMutex.RLock()
	defer p.jobMutex.RUnlock()

	count := 0
	for _, task := range p.jobs {
		if task.CompletedAt == nil && task.Error == nil {
			count++
		}
	}
	return count
}

// VerificationOrchestrator handles the verification aspect
type VerificationOrchestrator struct {
	logger    log.Logger
	processor *ApplicationProcessor
	pipeline  *CreditScoringPipeline

	// Seal tracking
	pendingSeals map[string]string // applicationID -> sealID
	sealMutex    sync.RWMutex
}

// NewVerificationOrchestrator creates a new orchestrator
func NewVerificationOrchestrator(logger log.Logger, processor *ApplicationProcessor, pipeline *CreditScoringPipeline) *VerificationOrchestrator {
	return &VerificationOrchestrator{
		logger:       logger,
		processor:    processor,
		pipeline:     pipeline,
		pendingSeals: make(map[string]string),
	}
}

// ProcessWithVerification processes an application with blockchain verification
func (o *VerificationOrchestrator) ProcessWithVerification(ctx context.Context, app *demotypes.LoanApplication) (*VerifiedResult, error) {
	startTime := time.Now()

	// Process the application
	result, err := o.processor.ProcessSync(ctx, app)
	if err != nil {
		return nil, fmt.Errorf("processing failed: %w", err)
	}

	// Create Digital Seal
	seal, err := o.pipeline.CreateDigitalSeal(app, result)
	if err != nil {
		return nil, fmt.Errorf("seal creation failed: %w", err)
	}

	// Track the seal
	o.sealMutex.Lock()
	o.pendingSeals[app.ApplicationID] = seal.Id
	o.sealMutex.Unlock()

	// Update result with seal ID
	result.SealID = seal.Id
	app.SealID = seal.Id

	verifiedResult := &VerifiedResult{
		Application:       app,
		Result:            result,
		SealID:            seal.Id,
		VerificationType:  result.VerificationType,
		TotalProcessingMs: time.Since(startTime).Milliseconds(),
	}

	o.logger.Info("Application processed with verification",
		"application_id", app.ApplicationID,
		"seal_id", seal.Id,
		"score", result.Score,
		"decision", result.Decision,
	)

	return verifiedResult, nil
}

// VerifiedResult contains the full verified result
type VerifiedResult struct {
	Application       *demotypes.LoanApplication     `json:"application"`
	Result            *demotypes.CreditScoringResult `json:"result"`
	SealID            string                         `json:"seal_id"`
	VerificationType  string                         `json:"verification_type"`
	TotalProcessingMs int64                          `json:"total_processing_ms"`
}

// GetSealID returns the seal ID for an application
func (o *VerificationOrchestrator) GetSealID(applicationID string) (string, error) {
	o.sealMutex.RLock()
	defer o.sealMutex.RUnlock()

	sealID, ok := o.pendingSeals[applicationID]
	if !ok {
		return "", fmt.Errorf("seal not found for application: %s", applicationID)
	}

	return sealID, nil
}

// SimulateConsensusVerification simulates the consensus verification process
func (o *VerificationOrchestrator) SimulateConsensusVerification(ctx context.Context, sealID string) (*ConsensusVerificationResult, error) {
	// Simulate validators agreeing on the result
	validators := []string{
		"aethelredvaloper1abc...",
		"aethelredvaloper1def...",
		"aethelredvaloper1ghi...",
		"aethelredvaloper1jkl...",
		"aethelredvaloper1mno...",
	}

	// Generate simulated attestations
	attestations := make([]ValidatorAttestation, len(validators))
	for i, validator := range validators {
		h := sha256.New()
		h.Write([]byte(sealID))
		h.Write([]byte(validator))
		h.Write([]byte(time.Now().String()))

		attestations[i] = ValidatorAttestation{
			ValidatorAddress: validator,
			OutputHash:       hex.EncodeToString(h.Sum(nil)[:16]),
			Timestamp:        time.Now().UTC(),
			Platform:         "aws-nitro",
			Agreed:           true,
		}
	}

	result := &ConsensusVerificationResult{
		SealID:             sealID,
		Verified:           true,
		TotalValidators:    len(validators),
		AgreementCount:     len(validators),
		Attestations:       attestations,
		ConsensusTimestamp: time.Now().UTC(),
		BlockHeight:        100, // Simulated
	}

	o.logger.Info("Consensus verification simulated",
		"seal_id", sealID,
		"validators", len(validators),
		"agreed", result.AgreementCount,
	)

	return result, nil
}

// ConsensusVerificationResult contains consensus verification result
type ConsensusVerificationResult struct {
	SealID             string                 `json:"seal_id"`
	Verified           bool                   `json:"verified"`
	TotalValidators    int                    `json:"total_validators"`
	AgreementCount     int                    `json:"agreement_count"`
	Attestations       []ValidatorAttestation `json:"attestations"`
	ConsensusTimestamp time.Time              `json:"consensus_timestamp"`
	BlockHeight        int64                  `json:"block_height"`
}

// ValidatorAttestation represents a validator's attestation
type ValidatorAttestation struct {
	ValidatorAddress string    `json:"validator_address"`
	OutputHash       string    `json:"output_hash"`
	Timestamp        time.Time `json:"timestamp"`
	Platform         string    `json:"platform"`
	Agreed           bool      `json:"agreed"`
}
