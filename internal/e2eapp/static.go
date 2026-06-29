package main

import "embed"

// staticFiles embeds the test-only browser page served by the e2e app.
//
//go:embed static/*
var staticFiles embed.FS
