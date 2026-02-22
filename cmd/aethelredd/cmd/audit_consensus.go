package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	aethelredapp "github.com/aethelred/aethelred/app"
	"github.com/spf13/cobra"
)

func auditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run deterministic audit checks",
	}
	cmd.AddCommand(auditConsensusEvidenceCommand())
	return cmd
}

func auditConsensusEvidenceCommand() *cobra.Command {
	var (
		requestFile string
		pretty      bool
	)

	cmd := &cobra.Command{
		Use:   "consensus-evidence",
		Short: "Audit injected consensus evidence against commit vote totals",
		Long: `Run the same injected consensus evidence checks used by ProcessProposal.

The request file must be JSON with:
- consensus_threshold (optional; clamped to minimum 67)
- proposed_last_commit (abci.CommitInfo JSON)
- txs (array of tx payloads; each entry can be JSON object, hex string, or base64 string)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if requestFile == "" {
				return fmt.Errorf("--request-file is required")
			}

			payload, err := os.ReadFile(requestFile)
			if err != nil {
				return fmt.Errorf("read request file: %w", err)
			}

			var req aethelredapp.ConsensusEvidenceAuditRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				return fmt.Errorf("parse request JSON: %w", err)
			}

			resp, err := aethelredapp.RunConsensusEvidenceAudit(req)
			if err != nil {
				return err
			}

			var out []byte
			if pretty {
				out, err = json.MarshalIndent(resp, "", "  ")
			} else {
				out, err = json.Marshal(resp)
			}
			if err != nil {
				return fmt.Errorf("marshal response: %w", err)
			}

			_, err = cmd.OutOrStdout().Write(append(out, '\n'))
			return err
		},
	}

	cmd.Flags().StringVar(&requestFile, "request-file", "", "Path to JSON request payload")
	cmd.Flags().BoolVar(&pretty, "pretty", true, "Pretty-print JSON output")
	return cmd
}
