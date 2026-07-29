// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package timesync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stacklok/go-microvm/ssh"
)

// The SSH client is the intended production GuestRunner.
var _ GuestRunner = (*ssh.Client)(nil)

// fakeRunner scripts the guest side: Run returns the configured date output,
// RunSudo records the step commands it receives.
type fakeRunner struct {
	dateOutput string
	runErr     error
	sudoErr    error

	runCalls  atomic.Int64
	sudoCmds  []string
	sudoCalls atomic.Int64
}

func (f *fakeRunner) Run(_ context.Context, _ string) (string, error) {
	f.runCalls.Add(1)
	return f.dateOutput, f.runErr
}

func (f *fakeRunner) RunSudo(_ context.Context, cmd string) (string, error) {
	f.sudoCalls.Add(1)
	f.sudoCmds = append(f.sudoCmds, cmd)
	return "", f.sudoErr
}

func TestSyncOnce(t *testing.T) {
	// Host clock is pinned so skew math is deterministic.
	hostNow := time.Unix(1_753_700_000, 0)

	tests := []struct {
		name        string
		guestEpoch  int64
		wantStepped bool
		wantSkew    time.Duration
	}{
		{
			name:        "guest behind beyond threshold steps forward",
			guestEpoch:  hostNow.Unix() - 2203,
			wantStepped: true,
			wantSkew:    -2203 * time.Second,
		},
		{
			name:        "guest in sync does not step",
			guestEpoch:  hostNow.Unix(),
			wantStepped: false,
			wantSkew:    0,
		},
		{
			name:        "guest ahead beyond threshold steps back",
			guestEpoch:  hostNow.Unix() + 30,
			wantStepped: true,
			wantSkew:    30 * time.Second,
		},
		{
			name:        "skew within threshold is left alone",
			guestEpoch:  hostNow.Unix() - 1,
			wantStepped: false,
			wantSkew:    -1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &fakeRunner{dateOutput: fmt.Sprintf("%d\n", tt.guestEpoch)}
			s := New(runner)
			s.now = func() time.Time { return hostNow }

			res, err := s.SyncOnce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if res.Stepped != tt.wantStepped {
				t.Errorf("Stepped = %v, want %v", res.Stepped, tt.wantStepped)
			}
			if res.Skew != tt.wantSkew {
				t.Errorf("Skew = %v, want %v", res.Skew, tt.wantSkew)
			}
			if tt.wantStepped {
				if len(runner.sudoCmds) != 1 {
					t.Fatalf("sudo commands = %v, want exactly one", runner.sudoCmds)
				}
				want := fmt.Sprintf("date -u -s @%d", hostNow.Unix())
				if runner.sudoCmds[0] != want {
					t.Errorf("step command = %q, want %q", runner.sudoCmds[0], want)
				}
			} else if runner.sudoCalls.Load() != 0 {
				t.Errorf("unexpected step commands: %v", runner.sudoCmds)
			}
		})
	}
}

func TestSyncOnceReadError(t *testing.T) {
	runner := &fakeRunner{runErr: errors.New("ssh: connection refused")}
	s := New(runner)
	_, err := s.SyncOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v", err)
	}
	if runner.sudoCalls.Load() != 0 {
		t.Error("stepped despite read error")
	}
}

func TestSyncOnceBadGuestOutput(t *testing.T) {
	runner := &fakeRunner{dateOutput: "date: invalid option -- u\n"}
	s := New(runner)
	_, err := s.SyncOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "parse guest time") {
		t.Fatalf("err = %v", err)
	}
}

func TestSyncOnceStepError(t *testing.T) {
	runner := &fakeRunner{dateOutput: "100\n", sudoErr: errors.New("doas: not permitted")}
	s := New(runner)
	_, err := s.SyncOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("err = %v", err)
	}
}

func TestWithThreshold(t *testing.T) {
	hostNow := time.Unix(1_753_700_000, 0)
	// 30s behind: beyond the default 2s threshold, within a custom 60s one.
	runner := &fakeRunner{dateOutput: fmt.Sprintf("%d\n", hostNow.Unix()-30)}
	s := New(runner, WithThreshold(60*time.Second))
	s.now = func() time.Time { return hostNow }

	res, err := s.SyncOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Stepped {
		t.Error("stepped despite skew within custom threshold")
	}
}

func TestRunSyncsImmediatelyThenPeriodically(t *testing.T) {
	runner := &fakeRunner{dateOutput: "100\n"} // hugely behind; every tick steps
	s := New(runner, WithInterval(10*time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := s.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	// One immediate sync plus at least one ticker firing.
	if n := runner.runCalls.Load(); n < 2 {
		t.Errorf("guest clock reads = %d, want >= 2", n)
	}
}

func TestRunKeepsGoingAfterSyncError(t *testing.T) {
	runner := &fakeRunner{dateOutput: "100\n", runErr: errors.New("ssh flake")}
	s := New(runner, WithInterval(10*time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	err := s.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded (loop must survive sync errors)", err)
	}
	if n := runner.runCalls.Load(); n < 2 {
		t.Errorf("guest clock reads = %d, want >= 2 despite errors", n)
	}
}
