package spilmankit

import (
	"os"

	"github.com/cashubtc/spilman-go/spilman"
	"gopkg.in/yaml.v3"
)

type SpilmanConfig struct {
	Mints            map[string][]string `yaml:"mints"`
	MinExpirySeconds uint64              `yaml:"min_expiry_seconds"`
	PricingScale     uint64              `yaml:"pricing_scale"`
	Storage          struct {
		Type string `yaml:"type"`
		Path string `yaml:"path"`
	} `yaml:"storage"`
	Pricing PricingTable `yaml:"pricing"`
}

type ConfigurableSpilman struct {
	Config *SpilmanConfig
	Stores SpilmanStores
	Host   *BaseSpilmanHost
	Bridge *spilman.Bridge
}

func LoadFromYaml(configPath, secretKeyHex string) (*ConfigurableSpilman, error) {
	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config SpilmanConfig
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, err
	}

	// Support MINT_URL override like Rust/TS/Python
	if mintUrl := os.Getenv("MINT_URL"); mintUrl != "" {
		allUnits := []string{}
		for u := range config.Pricing {
			allUnits = append(allUnits, u)
		}
		config.Mints = map[string][]string{mintUrl: allUnits}
	}

	var stores SpilmanStores
	if config.Storage.Type == "sqlite" && config.Storage.Path != "" {
		stores, err = NewSqliteStores(config.Storage.Path)
		if err != nil {
			return nil, err
		}
	} else {
		stores = NewInMemoryStores()
	}

	if config.MinExpirySeconds == 0 {
		config.MinExpirySeconds = 3600
	}
	if config.PricingScale == 0 {
		config.PricingScale = 1
	}

	host := NewBaseSpilmanHost(secretKeyHex, config.Mints, config.Pricing, stores, config.MinExpirySeconds, config.PricingScale)
	bridge := spilman.NewBridge(host)

	ctx := &ConfigurableSpilman{
		Config: &config,
		Stores: stores,
		Host:   host,
		Bridge: bridge,
	}

	// Initial keyset refresh (non-blocking)
	go ctx.InitializeKeysets()

	return ctx, nil
}

func (c *ConfigurableSpilman) InitializeKeysets() {
	for mintUrl := range c.Config.Mints {
		c.Host.RefreshAllKeysets(mintUrl)
	}
}

func (c *ConfigurableSpilman) Free() {
	if c.Bridge != nil {
		c.Bridge.Free()
	}
}
