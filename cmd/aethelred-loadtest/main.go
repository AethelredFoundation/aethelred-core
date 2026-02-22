package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aethelred/aethelred/tools/loadtest"
)

func main() {
	cfg := loadtest.DefaultConfig()

	var (
		scenario     string
		runAll       bool
		durationText string
		blockTime    string
		mode         string
	)

	flag.StringVar(&scenario, "scenario", "", "Named scenario to run (baseline, high-throughput, network-stress, byzantine, ...) ")
	flag.BoolVar(&runAll, "all-scenarios", false, "Run all predefined scenarios")
	flag.StringVar(&mode, "mode", cfg.Mode, "Execution mode: simulation|node")
	flag.IntVar(&cfg.NumValidators, "validators", cfg.NumValidators, "Number of validators")
	flag.IntVar(&cfg.JobsPerBlock, "jobs", cfg.JobsPerBlock, "Jobs per block")
	flag.IntVar(&cfg.NumBlocks, "blocks", cfg.NumBlocks, "Number of blocks to run")
	flag.StringVar(&durationText, "duration", cfg.Duration.String(), "Total test duration (e.g. 30m, 1h)")
	flag.StringVar(&blockTime, "block-time", cfg.BlockTime.String(), "Block interval (e.g. 6s)")
	flag.StringVar(&cfg.VerificationType, "verification", cfg.VerificationType, "Verification mode: tee|zkml|hybrid")
	flag.Float64Var(&cfg.ValidatorFailureRate, "validator-failure-rate", cfg.ValidatorFailureRate, "Validator failure rate [0..1]")
	flag.Float64Var(&cfg.ByzantineRate, "byzantine-rate", cfg.ByzantineRate, "Byzantine validator rate [0..1]")
	flag.StringVar(&cfg.OutputDir, "output-dir", cfg.OutputDir, "Directory for reports")
	flag.StringVar(&cfg.RPCEndpoint, "rpc-endpoint", cfg.RPCEndpoint, "RPC endpoint for --mode=node")
	flag.StringVar(&cfg.APIEndpoint, "api-endpoint", cfg.APIEndpoint, "API endpoint for --mode=node")
	flag.IntVar(&cfg.NodeConcurrency, "concurrency", cfg.NodeConcurrency, "request concurrency for --mode=node")
	flag.Parse()

	if runAll {
		if err := loadtest.RunAllScenarios(); err != nil {
			fmt.Fprintf(os.Stderr, "load test failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if scenario != "" {
		if err := loadtest.RunScenario(scenario); err != nil {
			fmt.Fprintf(os.Stderr, "scenario failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var err error
	cfg.Duration, err = time.ParseDuration(durationText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --duration: %v\n", err)
		os.Exit(1)
	}
	cfg.Mode = mode

	cfg.BlockTime, err = time.ParseDuration(blockTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --block-time: %v\n", err)
		os.Exit(1)
	}

	if cfg.Mode != "simulation" && cfg.Mode != "node" {
		fmt.Fprintln(os.Stderr, "--mode must be one of: simulation, node")
		os.Exit(1)
	}
	if cfg.Mode == "simulation" {
		if cfg.NumValidators < 4 {
			fmt.Fprintln(os.Stderr, "--validators must be >= 4 for meaningful quorum simulation")
			os.Exit(1)
		}
		if cfg.JobsPerBlock < 1 {
			fmt.Fprintln(os.Stderr, "--jobs must be >= 1")
			os.Exit(1)
		}
		if cfg.NumBlocks < 1 {
			fmt.Fprintln(os.Stderr, "--blocks must be >= 1")
			os.Exit(1)
		}
	}
	if cfg.Mode == "node" {
		if cfg.NodeConcurrency < 1 {
			fmt.Fprintln(os.Stderr, "--concurrency must be >= 1 in node mode")
			os.Exit(1)
		}
	}

	if err := loadtest.RunLoadTest(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "load test failed: %v\n", err)
		os.Exit(1)
	}
}
