module github.com/victorcondackdev/hsm-sim-dotnet/tools/vecgen

go 1.22

// The generator runs against a local checkout of the Go implementation,
// cloned next to this repository (../hsm-sim-go relative to the repository root).
replace github.com/victorcondackdev/hsm-sim-go => ../../../hsm-sim-go

require github.com/victorcondackdev/hsm-sim-go v0.0.0-00010101000000-000000000000
