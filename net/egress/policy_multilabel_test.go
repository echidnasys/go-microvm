// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import "testing"

// "**.domain" is the explicit multi-label wildcard form. In this DNS-level
// policy "*.domain" already matches any depth, so "**." is an alias here —
// but proxies layered above match "*." against exactly one label, so
// operators write "**." when they mean deep coverage. The policy must not
// treat the extra star as a literal character.
func TestDoubleStarWildcard(t *testing.T) {
	p := NewPolicy([]HostSpec{{Name: "**.amazonaws.com"}})
	for _, host := range []string{"s3.amazonaws.com", "sqs.us-east-1.amazonaws.com"} {
		if !p.IsAllowed(host) {
			t.Errorf("**.amazonaws.com should allow %s", host)
		}
	}
	if p.IsAllowed("amazonaws.com") {
		t.Error("**.amazonaws.com must not match the bare apex")
	}
	if p.IsAllowed("evil-amazonaws.com") {
		t.Error("**.amazonaws.com must not match a non-subdomain suffix")
	}
}
