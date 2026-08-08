// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hosted

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"

	"github.com/stacklok/go-microvm/internal/logbridge"
	propnet "github.com/stacklok/go-microvm/net"
	"github.com/stacklok/go-microvm/net/egress"
	"github.com/stacklok/go-microvm/net/firewall"
	"github.com/stacklok/go-microvm/net/topology"
)

const socketName = "hosted-net.sock"

// Provider runs a gvisor-tap-vsock VirtualNetwork in the caller's process
// and exposes a Unix socket for go-microvm-runner to connect to.
type Provider struct {
	mu              sync.Mutex
	vn              *virtualnetwork.VirtualNetwork
	listener        net.Listener
	sockPath        string
	relay           *firewall.Relay
	bgCtx           context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	pendingServices []Service
	runningServices []runningService
	forwardLocals   []string
}

// NewProvider creates a new hosted network provider.
func NewProvider() *Provider {
	return &Provider{}
}

// Start launches the virtual network and begins listening on a Unix socket.
// It satisfies the [net.Provider] interface.
func (p *Provider) Start(ctx context.Context, cfg propnet.Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.vn != nil {
		return fmt.Errorf("provider already started")
	}

	// Redirect gvisor-tap-vsock's logrus output through slog so it follows
	// the caller's logging configuration (e.g. file-based logging) instead
	// of polluting stderr during the terminal session.
	logbridge.RedirectLogrus()

	// Build port forward map: bind BOTH IPv4 127.0.0.1 and IPv6 [::1] for each
	// host port, so a browser hitting "localhost:<host>" connects regardless of
	// which family it resolves first.
	forwards := make(map[string]string, len(cfg.Forwards)*2)
	for _, pf := range cfg.Forwards {
		guestAddr := fmt.Sprintf("%s:%d", topology.GuestIP, pf.Guest)
		forwards[fmt.Sprintf("127.0.0.1:%d", pf.Host)] = guestAddr
		forwards[fmt.Sprintf("[::1]:%d", pf.Host)] = guestAddr
	}
	// Create the virtual network stack WITHOUT forwards. Passing Forwards
	// into virtualnetwork.New is a trap: on a partial bind failure (one
	// host port taken) it returns only an error, and the listeners it had
	// already bound are unreachable — they live for the daemon's lifetime,
	// so every retry of the same session fails on the leaked ports until a
	// daemon restart. Exposing each forward ourselves after New makes a
	// failure unwindable.
	vn, err := virtualnetwork.New(&types.Configuration{
		Subnet:            topology.Subnet,
		GatewayIP:         topology.GatewayIP,
		GatewayMacAddress: topology.GatewayMAC,
		MTU:               topology.MTU,
	})
	if err != nil {
		return fmt.Errorf("create virtual network: %w", err)
	}

	// Bind the host-side forwards one at a time; on any failure release
	// what was already bound and fail Start cleanly, so the caller can
	// retry once the colliding port frees up. The bound list also serves
	// Stop, which unexposes the forwards of a successful Start.
	bound := make([]string, 0, len(forwards))
	// fail releases everything Start has acquired so far. Every error
	// return below MUST go through it: a half-started provider that keeps
	// listeners (or the services it started) alive wedges all later
	// sessions that reuse the same ports.
	fail := func(err error) error {
		unexposeForwards(vn, bound)
		p.forwardLocals = nil
		p.vn = nil
		return err
	}
	for local, guestAddr := range forwards {
		if err := exposeForward(vn, local, guestAddr); err != nil {
			return fail(fmt.Errorf("expose port forward %s: %w", local, err))
		}
		bound = append(bound, local)
	}
	p.forwardLocals = bound
	p.vn = vn

	// Start any registered services on the virtual network.
	if err := p.startServices(); err != nil {
		p.shutdownServices(p.snapshotAndClearServices())
		return fail(fmt.Errorf("start services: %w", err))
	}

	// Prepare the Unix socket path.
	p.sockPath = filepath.Join(cfg.LogDir, socketName)

	// Remove stale socket if present.
	if err := os.Remove(p.sockPath); err != nil && !os.IsNotExist(err) {
		p.shutdownServices(p.snapshotAndClearServices())
		return fail(fmt.Errorf("remove stale socket: %w", err))
	}

	listener, err := net.Listen("unix", p.sockPath)
	if err != nil {
		p.shutdownServices(p.snapshotAndClearServices())
		return fail(fmt.Errorf("listen on unix socket: %w", err))
	}
	p.listener = listener

	// Set up firewall relay (with optional egress policy).
	bgCtx, cancel := context.WithCancel(ctx)
	p.bgCtx = bgCtx
	p.cancel = cancel

	if cfg.EgressPolicy != nil {
		p.relay = p.buildEgressRelay(bgCtx, cfg)
	} else if len(cfg.FirewallRules) > 0 {
		filter := firewall.NewFilter(cfg.FirewallRules, cfg.FirewallDefaultAction)
		p.relay = firewall.NewRelay(filter)
		filter.StartExpiry(bgCtx)
	}

	// Accept connections in the background.
	p.wg.Add(1)
	go p.acceptLoop()

	return nil
}

// SocketPath returns the path to the Unix socket for go-microvm-runner.
func (p *Provider) SocketPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sockPath
}

// Stop terminates the provider and cleans up resources.
func (p *Provider) Stop() {
	p.mu.Lock()
	services := p.snapshotAndClearServices()
	cancel := p.cancel
	listener := p.listener
	sockPath := p.sockPath
	vn := p.vn
	forwardLocals := p.forwardLocals
	p.forwardLocals = nil
	p.mu.Unlock()

	unexposeForwards(vn, forwardLocals)

	// Shut down HTTP services outside the lock so Shutdown's blocking
	// does not prevent other callers from acquiring the mutex.
	p.shutdownServices(services)

	if cancel != nil {
		cancel()
	}

	if listener != nil {
		_ = listener.Close()
	}

	// Wait for the accept loop to finish.
	p.wg.Wait()

	// Clean up the socket file.
	if sockPath != "" {
		_ = os.Remove(sockPath)
	}
}

// unexposeForwards closes the host-side port-forward listeners that
// virtualnetwork.New bound from the Forwards map. gvisor-tap-vsock has no
// VirtualNetwork teardown API, so this drives the forwarder's unexpose
// endpoint through the in-process services mux — the same handler external
// clients use — which closes each underlying host listener.
// exposeForward binds one host-side port forward through the virtual
// network's services mux — the same endpoint unexposeForwards releases
// through, so a forward bound here is always individually releasable.
func exposeForward(vn *virtualnetwork.VirtualNetwork, local, remote string) error {
	body, err := json.Marshal(types.ExposeRequest{Protocol: types.TCP, Local: local, Remote: remote})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "/services/forwarder/expose", bytes.NewReader(body))
	if err != nil {
		return err
	}
	rec := &statusRecorder{}
	vn.ServicesMux().ServeHTTP(rec, req)
	if rec.status != http.StatusOK {
		return fmt.Errorf("services mux returned status %d", rec.status)
	}
	return nil
}

func unexposeForwards(vn *virtualnetwork.VirtualNetwork, locals []string) {
	if vn == nil || len(locals) == 0 {
		return
	}
	mux := vn.ServicesMux()
	for _, local := range locals {
		body, err := json.Marshal(types.UnexposeRequest{Protocol: types.TCP, Local: local})
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, "/services/forwarder/unexpose", bytes.NewReader(body))
		if err != nil {
			continue
		}
		rec := &statusRecorder{}
		mux.ServeHTTP(rec, req)
		if rec.status != http.StatusOK {
			slog.Warn("unexpose port forward failed", "local", local, "status", rec.status)
		}
	}
}

// statusRecorder is the minimal http.ResponseWriter needed to drive the
// services mux in-process; only the response status is of interest.
type statusRecorder struct{ status int }

func (r *statusRecorder) Header() http.Header { return http.Header{} }
func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return len(b), nil
}
func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

// VirtualNetwork returns the underlying gvisor-tap-vsock VirtualNetwork.
// Returns nil before Start is called.
func (p *Provider) VirtualNetwork() *virtualnetwork.VirtualNetwork {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.vn
}

// Relay returns the firewall relay, or nil if no firewall rules are configured.
func (p *Provider) Relay() *firewall.Relay {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.relay
}

// buildEgressRelay constructs a relay with DNS-based egress filtering.
// It creates implicit rules for DNS, DHCP, and port forwards, then
// wires up a DynamicRules set, Policy, and DNSInterceptor.
func (p *Provider) buildEgressRelay(ctx context.Context, cfg propnet.Config) *firewall.Relay {
	_, gatewayNet, _ := net.ParseCIDR(topology.GatewayIP + "/32")
	_, broadcastNet, _ := net.ParseCIDR("255.255.255.255/32")

	// Build implicit rules that are always needed.
	implicitRules := []firewall.Rule{
		// Allow DNS to gateway.
		{Direction: firewall.Egress, Action: firewall.Allow, Protocol: 17,
			DstCIDR: *gatewayNet, DstPort: 53},
		// Allow DHCP (client -> server): to gateway and broadcast.
		{Direction: firewall.Egress, Action: firewall.Allow, Protocol: 17,
			DstCIDR: *gatewayNet, DstPort: 67},
		{Direction: firewall.Egress, Action: firewall.Allow, Protocol: 17,
			DstCIDR: *broadcastNet, DstPort: 67},
		// Allow DHCP (server -> client): from gateway only.
		{Direction: firewall.Ingress, Action: firewall.Allow, Protocol: 17,
			SrcCIDR: *gatewayNet, SrcPort: 67},
	}

	// Allow ingress on port-forwarded ports.
	for _, pf := range cfg.Forwards {
		implicitRules = append(implicitRules, firewall.Rule{
			Direction: firewall.Ingress,
			Action:    firewall.Allow,
			Protocol:  6,
			DstPort:   pf.Guest,
		})
	}

	// Allow egress to hosted services on the gateway IP.
	// Services bind inside the VirtualNetwork on the gateway address,
	// but packets still traverse the firewall relay — same pattern as DNS/DHCP.
	for _, svc := range p.pendingServices {
		implicitRules = append(implicitRules, firewall.Rule{
			Direction: firewall.Egress,
			Action:    firewall.Allow,
			Protocol:  6, // TCP
			DstCIDR:   *gatewayNet,
			DstPort:   svc.Port,
		})
	}

	// Prepend implicit rules before user-provided rules.
	allRules := make([]firewall.Rule, 0, len(implicitRules)+len(cfg.FirewallRules))
	allRules = append(allRules, implicitRules...)
	allRules = append(allRules, cfg.FirewallRules...)

	// Build egress policy components.
	hosts := make([]egress.HostSpec, len(cfg.EgressPolicy.AllowedHosts))
	for i, h := range cfg.EgressPolicy.AllowedHosts {
		hosts[i] = egress.HostSpec{
			Name:     h.Name,
			Ports:    h.Ports,
			Protocol: h.Protocol,
		}
	}

	gwIP := net.ParseIP(topology.GatewayIP).To4()
	var gatewayIPAddr [4]byte
	copy(gatewayIPAddr[:], gwIP)

	dynamicRules := firewall.NewDynamicRules()
	policy := egress.NewPolicy(hosts)
	interceptor := egress.NewDNSInterceptor(policy, dynamicRules, gatewayIPAddr)

	filter := firewall.NewFilterWithDynamic(allRules, firewall.Deny, dynamicRules)
	filter.StartExpiry(ctx)

	slog.Info("egress policy active",
		"allowed_hosts", len(cfg.EgressPolicy.AllowedHosts),
		"implicit_rules", len(implicitRules),
	)

	return firewall.NewRelayWithDNSHook(filter, interceptor)
}

// acceptLoop accepts connections from go-microvm-runner and bridges them
// to the VirtualNetwork.
func (p *Provider) acceptLoop() {
	defer p.wg.Done()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			// Listener closed during Stop — expected.
			return
		}

		p.wg.Add(1)
		go p.handleConn(conn)
	}
}

// handleConn bridges a single runner connection to the VirtualNetwork.
func (p *Provider) handleConn(runnerConn net.Conn) {
	defer p.wg.Done()

	p.mu.Lock()
	vn := p.vn
	relay := p.relay
	bgCtx := p.bgCtx
	p.mu.Unlock()

	if relay != nil {
		// With firewall: create an in-memory pipe. The relay sits between
		// the runner connection and one end of the pipe; the other end
		// is passed to AcceptQemu.
		vnConn, relayConn := net.Pipe()

		// Start the relay between runner and the pipe end.
		go func() {
			if err := relay.Run(bgCtx, runnerConn, relayConn); err != nil {
				slog.Debug("relay ended", "error", err)
			}
		}()

		// Bridge pipe's other end to the VirtualNetwork.
		if err := vn.AcceptQemu(bgCtx, vnConn); err != nil {
			slog.Debug("AcceptQemu ended", "error", err)
		}
	} else {
		// Without firewall: direct bridge.
		if err := vn.AcceptQemu(bgCtx, runnerConn); err != nil {
			slog.Debug("AcceptQemu ended", "error", err)
		}
	}
}
