package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"

	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"
)

const upstreamCommit = "a14aa98ab8408547083d4411091c5fbaf5b47d8e"

type capabilities struct {
	DirectFS      bool   `json:"direct_fs"`
	RunningSystem bool   `json:"running_system"`
	Network       string `json:"network"`
	OS            string `json:"os"`
}

type inventory struct {
	Schema          string       `json:"schema"`
	UpstreamCommit  string       `json:"upstream_commit"`
	ProfileSHA256   string       `json:"profile_sha256"`
	GeneratorSHA256 string       `json:"generator_sha256"`
	Presets         []string     `json:"presets"`
	Capabilities    capabilities `json:"capabilities"`
	Plugins         []string     `json:"plugins"`
}

func main() {
	profile := flag.String("profile", "", "pinned native profile to bind")
	generator := flag.String("generator-sha256", "", "source digest for this inventory generator")
	flag.Parse()
	if *profile == "" || !isDigest(*generator) {
		fail("profile and valid generator digest are required")
	}
	profileBytes, err := os.ReadFile(*profile)
	if err != nil {
		fail("cannot read profile: %v", err)
	}
	profileHash := sha256.Sum256(profileBytes)
	selected := plugin.FilterByCapabilities(
		scalibrplugin.Resolve([]string{"lockfile", "sbom", "directory"}, nil),
		&plugin.Capabilities{
			DirectFS:      true,
			RunningSystem: true,
			Network:       plugin.NetworkOffline,
			OS:            plugin.OSLinux,
		},
	)
	names := make([]string, 0, len(selected))
	for _, item := range selected {
		names = append(names, item.Name())
	}
	sort.Strings(names)
	if len(names) == 0 || hasDuplicates(names) {
		fail("pinned profile resolves to an empty or duplicate extractor inventory")
	}
	result := inventory{
		Schema:          "factory.osv-extractor-inventory.v1",
		UpstreamCommit:  upstreamCommit,
		ProfileSHA256:   hex.EncodeToString(profileHash[:]),
		GeneratorSHA256: *generator,
		Presets:         []string{"lockfile", "sbom", "directory"},
		Capabilities: capabilities{
			DirectFS: true, RunningSystem: true, Network: "offline", OS: "linux",
		},
		Plugins: names,
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fail("cannot encode inventory: %v", err)
	}
}

func isDigest(value string) bool {
	return regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(value)
}

func hasDuplicates(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
