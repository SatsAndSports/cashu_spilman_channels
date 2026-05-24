module github.com/cashubtc/cdk-spilman-kit-go

go 1.24.0

require (
	github.com/cashubtc/spilman-go/spilman v0.1.0
	github.com/mattn/go-sqlite3 v1.14.22
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e

replace github.com/cashubtc/spilman-go/spilman => ../../crates/cdk-spilman-go/spilman
