module github.com/cashubtc/spilman-go/examples/ascii-art

go 1.22

// For local development, use the local spilman package
replace github.com/cashubtc/spilman-go/spilman => ../../crates/cdk-spilman-go/spilman

replace github.com/cashubtc/cdk-spilman-kit-go => ../../integration-kits/go

require (
	github.com/cashubtc/cdk-spilman-kit-go v0.1.0
	github.com/cashubtc/spilman-go/spilman v0.1.0
	github.com/common-nighthawk/go-figure v0.0.0-20210622060536-734e95fb86be
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
)

require (
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
