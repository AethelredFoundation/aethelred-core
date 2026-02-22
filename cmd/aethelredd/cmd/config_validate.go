package cmd

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/cosmos/cosmos-sdk/server"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"
)

func validateAppConfig(cmd *cobra.Command) error {
	serverCtx := server.GetServerContextFromCmd(cmd)

	var cfg AppConfig
	if err := serverCtx.Viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("failed to decode app config: %w", err)
	}

	if err := cfg.ValidateBasic(); err != nil {
		return err
	}

	return nil
}

// ValidateBasic performs comprehensive validation of app.toml configuration.
func (c AppConfig) ValidateBasic() error {
	if err := c.Config.ValidateBasic(); err != nil {
		return err
	}

	if _, err := sdk.ParseDecCoins(c.MinGasPrices); err != nil {
		return fmt.Errorf("invalid min gas prices: %w", err)
	}

	if c.API.Enable {
		if err := validateListenAddress("api.address", c.API.Address); err != nil {
			return err
		}
		if c.API.MaxOpenConnections <= 0 {
			return fmt.Errorf("api.max-open-connections must be positive")
		}
	}

	if c.GRPC.Enable {
		if err := validateListenAddress("grpc.address", c.GRPC.Address); err != nil {
			return err
		}
		if c.GRPC.MaxRecvMsgSize <= 0 || c.GRPC.MaxSendMsgSize <= 0 {
			return fmt.Errorf("grpc max message sizes must be positive")
		}
	}

	if err := validateTEEConfig(c.TEE); err != nil {
		return err
	}

	return nil
}

func validateTEEConfig(cfg TEEConfig) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "disabled"
	}

	allowed := map[string]bool{
		"disabled":        true,
		"remote":          true,
		"http":            true,
		"nitro":           true,
		"aws-nitro":       true,
		"nitro-simulated": true,
		"mock":            true,
	}
	if !allowed[mode] {
		return fmt.Errorf("tee.mode must be one of disabled, remote, http, nitro, aws-nitro, nitro-simulated, mock")
	}

	switch mode {
	case "remote", "http", "nitro", "aws-nitro":
		if cfg.Endpoint == "" {
			return fmt.Errorf("tee.endpoint is required when tee.mode=%s", mode)
		}
		if err := validateHTTPEndpoint("tee.endpoint", cfg.Endpoint); err != nil {
			return err
		}
	case "nitro-simulated":
		if cfg.Endpoint != "" && !strings.HasPrefix(cfg.Endpoint, "simulated://") {
			// allow custom simulated schemes but require explicit prefix
			return fmt.Errorf("tee.endpoint must use simulated:// for nitro-simulated mode")
		}
	}

	return nil
}

func validateListenAddress(field, addr string) error {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return fmt.Errorf("%s cannot be empty", field)
	}

	if strings.HasPrefix(trimmed, "unix://") {
		if len(strings.TrimPrefix(trimmed, "unix://")) == 0 {
			return fmt.Errorf("%s unix socket path is empty", field)
		}
		return nil
	}

	if strings.HasPrefix(trimmed, "tcp://") {
		trimmed = strings.TrimPrefix(trimmed, "tcp://")
	}

	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return fmt.Errorf("%s must be host:port (or tcp://host:port): %w", field, err)
	}
	if host == "" {
		return fmt.Errorf("%s host cannot be empty", field)
	}
	if port == "" {
		return fmt.Errorf("%s port cannot be empty", field)
	}
	if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
		return fmt.Errorf("%s port must be in [1, 65535]", field)
	}

	return nil
}

func validateHTTPEndpoint(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s must be a valid URL: %w", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s must use http or https scheme", field)
	}
	if u.Host == "" {
		return fmt.Errorf("%s must include host", field)
	}
	return nil
}
