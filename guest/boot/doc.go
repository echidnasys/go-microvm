// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package boot orchestrates the guest VM boot sequence: essential mounts,
// networking, workspace mount, kernel hardening, environment loading,
// capability dropping, optional SSH server start, and optional seccomp
// filtering. It uses functional options to replace the hardcoded values
// found in consumer-specific init processes, making it reusable across
// different guest VM configurations.
//
// # SSH support is build-tag gated
//
// The SSH bring-up (authorized_keys parsing, host-key loading, listener
// start) is compiled in by default. Consumers that do not want the SSH
// path linked into their guest init binary can pass -tags=nosshd at
// build time: this swaps in a stub that does not import
// golang.org/x/crypto/ssh, and [Run] then refuses to start unless the
// caller has signalled SSH-off via [WithoutSSH].
//
// Consumers that need SSH (e.g. brood-box) need no build-time change.
// Consumers that don't (e.g. bbox-k8s, which uses ttrpc-over-vsock)
// build their init binary with -tags=nosshd and call [WithoutSSH] from
// it; the resulting binary has no SSH dependency in its link-time graph.
package boot
