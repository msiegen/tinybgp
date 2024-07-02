module github.com/msiegen/tinybgp

// To use this module you need a minimum Go version of 1.22 and the Rangefunc
// experiment enabled. For more detail about GOEXPERIMENT=rangefunc, see
// https://go.dev/wiki/RangefuncExperiment. This requirement will go away upon
// upgrading to Go 1.23.
go 1.22

require (
	github.com/google/go-cmp v0.6.0
	github.com/jpillora/backoff v1.0.0
	github.com/osrg/gobgp/v3 v3.28.0
	golang.org/x/sys v0.21.0
)
