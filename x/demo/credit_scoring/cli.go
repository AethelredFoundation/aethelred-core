package credit_scoring

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"cosmossdk.io/log"

	demotypes "github.com/aethelred/aethelred/x/demo/types"
)

// CLI provides command-line interface for the credit scoring demo
type CLI struct {
	logger       log.Logger
	pipeline     *CreditScoringPipeline
	processor    *ApplicationProcessor
	orchestrator *VerificationOrchestrator
}

// NewCLI creates a new CLI instance
func NewCLI(logger log.Logger) *CLI {
	pipeline := NewCreditScoringPipeline(logger, DefaultPipelineConfig())
	processor := NewApplicationProcessor(logger, pipeline, DefaultProcessorConfig())
	orchestrator := NewVerificationOrchestrator(logger, processor, pipeline)

	// Start processor
	processor.Start()

	return &CLI{
		logger:       logger,
		pipeline:     pipeline,
		processor:    processor,
		orchestrator: orchestrator,
	}
}

// Close closes the CLI and stops the processor
func (c *CLI) Close() {
	c.processor.Stop()
}

// RunDemo runs the full demo flow
func (c *CLI) RunDemo(withVerification bool) error {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("           AETHELRED CREDIT SCORING VERIFICATION DEMO")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()

	scenarios := GetDemoScenarios()
	ctx := context.Background()

	// Group scenarios by expected decision
	approved := make([]*DemoScenario, 0)
	review := make([]*DemoScenario, 0)
	denied := make([]*DemoScenario, 0)

	for _, s := range scenarios {
		switch s.ExpectedDecision {
		case demotypes.LoanDecisionApproved:
			approved = append(approved, s)
		case demotypes.LoanDecisionReview:
			review = append(review, s)
		case demotypes.LoanDecisionDenied:
			denied = append(denied, s)
		}
	}

	// Run samples from each category
	fmt.Println("Running demo scenarios across credit spectrum...")

	// Run one from each category
	sampleScenarios := []*DemoScenario{
		approved[0], // Excellent credit
		review[0],   // Fair credit
		denied[0],   // Poor credit
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	for i, scenario := range sampleScenarios {
		fmt.Printf("\n%s Scenario %d: %s %s\n", strings.Repeat("-", 20), i+1, scenario.Name, strings.Repeat("-", 20))
		fmt.Printf("Category: %s | Expected: %s\n", scenario.Category, scenario.ExpectedDecision)
		fmt.Printf("Loan: $%.2f %s for %d months\n\n", scenario.LoanAmount, scenario.LoanType, scenario.LoanTerm)

		app := demotypes.NewLoanApplication(
			scenario.ApplicantID,
			scenario.LoanType,
			scenario.LoanAmount,
			scenario.LoanTerm,
			scenario.Features,
			"credit-score-v1",
			"demo-cli",
		)

		var result *demotypes.CreditScoringResult
		var sealID string

		if withVerification {
			verifiedResult, err := c.orchestrator.ProcessWithVerification(ctx, app)
			if err != nil {
				fmt.Printf("ERROR: %v\n", err)
				continue
			}
			result = verifiedResult.Result
			sealID = verifiedResult.SealID
		} else {
			var err error
			result, err = c.processor.ProcessSync(ctx, app)
			if err != nil {
				fmt.Printf("ERROR: %v\n", err)
				continue
			}
		}

		// Display results
		fmt.Fprintf(w, "Credit Score:\t%d (%s)\n", result.Score, result.ScoreCategory)
		fmt.Fprintf(w, "Default Probability:\t%.2f%%\n", result.DefaultProbability*100)
		fmt.Fprintf(w, "Decision:\t%s\n", strings.ToUpper(string(result.Decision)))
		fmt.Fprintf(w, "Confidence:\t%.1f%%\n", result.Confidence*100)
		w.Flush()

		if result.RecommendedRate != nil {
			fmt.Printf("Recommended Rate: %.2f%%\n", *result.RecommendedRate)
		}
		if result.RecommendedLimit != nil {
			fmt.Printf("Recommended Limit: $%.2f\n", *result.RecommendedLimit)
		}

		fmt.Println("\nRisk Factors:")
		for _, rf := range result.RiskFactors {
			fmt.Printf("  - %s (impact: %d)\n", rf.Description, rf.Impact)
		}

		if len(result.PositiveFactors) > 0 {
			fmt.Println("\nPositive Factors:")
			for _, pf := range result.PositiveFactors {
				fmt.Printf("  + %s\n", pf)
			}
		}

		if withVerification && sealID != "" {
			fmt.Printf("\nDigital Seal ID: %s\n", sealID)
			fmt.Printf("Verification Type: %s\n", result.VerificationType)
		}

		fmt.Printf("Processing Time: %dms\n", result.ProcessingTimeMs)
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                         DEMO SUMMARY")
	fmt.Println(strings.Repeat("=", 70))

	metrics := c.pipeline.GetMetrics()
	fmt.Printf("\nTotal Applications Processed: %d\n", metrics.ProcessedApplications)
	fmt.Printf("Approved: %d | Review: %d | Denied: %d\n",
		metrics.ApprovedApplications, metrics.ReviewApplications, metrics.DeniedApplications)
	fmt.Printf("Average Score: %.0f\n", metrics.AverageScore)
	fmt.Printf("Average Processing Time: %dms\n", metrics.AverageProcessingTimeMs)

	if withVerification {
		fmt.Println("\nAll results verified through TEE+zkML hybrid consensus.")
		fmt.Println("Digital Seals created for immutable audit trail.")
	}

	fmt.Println("\n" + strings.Repeat("=", 70))

	return nil
}

// ScoreApplication scores a single application
func (c *CLI) ScoreApplication(features *demotypes.CreditFeatures, loanType string, amount float64, term int, withVerification bool) (*demotypes.CreditScoringResult, error) {
	ctx := context.Background()

	app := demotypes.NewLoanApplication(
		fmt.Sprintf("cli-%d", time.Now().UnixNano()),
		loanType,
		amount,
		term,
		features,
		"credit-score-v1",
		"cli",
	)

	if withVerification {
		verifiedResult, err := c.orchestrator.ProcessWithVerification(ctx, app)
		if err != nil {
			return nil, err
		}
		return verifiedResult.Result, nil
	}

	return c.processor.ProcessSync(ctx, app)
}

// RunScenario runs a specific scenario by ID
func (c *CLI) RunScenario(scenarioID string, withVerification bool) (*demotypes.CreditScoringResult, error) {
	scenario := GetScenarioByID(scenarioID)
	if scenario == nil {
		return nil, fmt.Errorf("scenario not found: %s", scenarioID)
	}

	return c.ScoreApplication(
		scenario.Features,
		scenario.LoanType,
		scenario.LoanAmount,
		scenario.LoanTerm,
		withVerification,
	)
}

// ListScenarios lists all available scenarios
func (c *CLI) ListScenarios() {
	scenarios := GetDemoScenarios()

	fmt.Println("\nAvailable Demo Scenarios:")
	fmt.Println(strings.Repeat("-", 90))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID\tName\tCategory\tExpected\tLoan\n")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
		strings.Repeat("-", 25),
		strings.Repeat("-", 30),
		strings.Repeat("-", 10),
		strings.Repeat("-", 10),
		strings.Repeat("-", 15))

	for _, s := range scenarios {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t$%.0f\n",
			s.ID, s.Name, s.Category, s.ExpectedDecision, s.LoanAmount)
	}
	w.Flush()
}

// ListModels lists registered models
func (c *CLI) ListModels() {
	models := c.pipeline.ListModels()

	fmt.Println("\nRegistered Credit Scoring Models:")
	fmt.Println(strings.Repeat("-", 70))

	for _, m := range models {
		fmt.Printf("\nModel ID: %s\n", m.ModelID)
		fmt.Printf("Name: %s (v%s)\n", m.Name, m.Version)
		fmt.Printf("Status: %s\n", m.Status)
		fmt.Printf("Features: %d\n", m.InputSchema.FeatureCount)
		if m.Metrics != nil {
			fmt.Printf("AUC-ROC: %.3f | Accuracy: %.3f | KS: %.3f\n",
				m.Metrics.AUCROC, m.Metrics.Accuracy, m.Metrics.KSStatistic)
		}
		if m.Compliance != nil {
			fmt.Printf("Compliance: %v\n", m.Compliance.Frameworks)
		}
		fmt.Printf("Usage Count: %d\n", m.UsageCount)
	}
}

// ShowMetrics displays current metrics
func (c *CLI) ShowMetrics() {
	metrics := c.pipeline.GetMetrics()

	fmt.Println("\nPipeline Metrics:")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("Total Applications:      %d\n", metrics.TotalApplications)
	fmt.Printf("Processed Applications:  %d\n", metrics.ProcessedApplications)
	fmt.Printf("Approved:                %d\n", metrics.ApprovedApplications)
	fmt.Printf("Denied:                  %d\n", metrics.DeniedApplications)
	fmt.Printf("Manual Review:           %d\n", metrics.ReviewApplications)
	fmt.Printf("Failed:                  %d\n", metrics.FailedApplications)
	fmt.Printf("Average Score:           %.0f\n", metrics.AverageScore)
	fmt.Printf("Avg Processing Time:     %dms\n", metrics.AverageProcessingTimeMs)
	fmt.Printf("Queue Length:            %d\n", c.processor.GetQueueLength())
	fmt.Printf("Pending:                 %d\n", c.processor.GetPendingCount())
}

// ExportResults exports all results to JSON
func (c *CLI) ExportResults(filename string) error {
	apps := c.pipeline.ListApplications()

	output := struct {
		ExportedAt   time.Time                   `json:"exported_at"`
		Applications []*demotypes.LoanApplication `json:"applications"`
		Metrics      *PipelineMetrics            `json:"metrics"`
	}{
		ExportedAt:   time.Now().UTC(),
		Applications: apps,
		Metrics:      c.pipeline.GetMetrics(),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// InteractiveMode runs an interactive demo session
func (c *CLI) InteractiveMode() {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("         AETHELRED CREDIT SCORING - INTERACTIVE MODE")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\nCommands:")
	fmt.Println("  demo [verified]     - Run full demo")
	fmt.Println("  scenarios           - List available scenarios")
	fmt.Println("  run <scenario-id>   - Run specific scenario")
	fmt.Println("  models              - List registered models")
	fmt.Println("  metrics             - Show current metrics")
	fmt.Println("  export <file>       - Export results to JSON")
	fmt.Println("  help                - Show this help")
	fmt.Println("  quit                - Exit")
	fmt.Println()

	// Note: In production, this would use a proper readline library
	// For MVP, we just show the available commands
}

// QuickDemo runs a quick demonstration
func QuickDemo() {
	logger := log.NewNopLogger()
	cli := NewCLI(logger)
	defer cli.Close()

	cli.RunDemo(true)
}

// DemoCommand represents the demo command for the CLI
type DemoCommand struct {
	Name        string
	Description string
	Run         func(args []string) error
}

// GetDemoCommands returns available demo commands
func GetDemoCommands(cli *CLI) []DemoCommand {
	return []DemoCommand{
		{
			Name:        "demo",
			Description: "Run full credit scoring demo with all scenarios",
			Run: func(args []string) error {
				withVerification := len(args) > 0 && args[0] == "verified"
				return cli.RunDemo(withVerification)
			},
		},
		{
			Name:        "scenarios",
			Description: "List all available demo scenarios",
			Run: func(args []string) error {
				cli.ListScenarios()
				return nil
			},
		},
		{
			Name:        "run",
			Description: "Run a specific scenario by ID",
			Run: func(args []string) error {
				if len(args) < 1 {
					return fmt.Errorf("scenario ID required")
				}
				result, err := cli.RunScenario(args[0], len(args) > 1 && args[1] == "verified")
				if err != nil {
					return err
				}
				data, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(data))
				return nil
			},
		},
		{
			Name:        "models",
			Description: "List registered credit scoring models",
			Run: func(args []string) error {
				cli.ListModels()
				return nil
			},
		},
		{
			Name:        "metrics",
			Description: "Show pipeline metrics",
			Run: func(args []string) error {
				cli.ShowMetrics()
				return nil
			},
		},
		{
			Name:        "export",
			Description: "Export results to JSON file",
			Run: func(args []string) error {
				if len(args) < 1 {
					return fmt.Errorf("filename required")
				}
				return cli.ExportResults(args[0])
			},
		},
	}
}
