package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Agent struct {
	NodeID          string // ej: NODE-1
	NodeIP          string // ej: 192.168.1.51
	PodCIDR         string // ej: 10.244.1.0/24
	Bridge          Bridge
	ControlPlaneURL string
	Services        map[string]*Service

	//IPs already allocated inside PodCIDR shared by all services in 1 NODE (gateway included)
	//len(AllocatedIPs) is used as pointer to the next free IP
	//(valid pod IPs for /24: .2 - .254 -> 253 IPs; .0 network, .1 gateway, .255 broadcast are reserved)
	allocated map[string]bool

	RegistryPath      string // where pod binaries are taken from (<RegistryPath>/main)
	SecretManagerPath string // where pod env files are taken from (<SecretManagerPath>/env.local)
	PodsPath          string // one directory per pod (<PodsPath>/<podID>)
}

// DataDir holds everything the agent keeps on disk, absolute so it does not depend on
// the directory the agent was started from
const DataDir = "/var/lib/orchard"

type Bridge struct {
	Name      string // br0
	GatewayIP string
}

func NewAgent(nodeID, nodeIP, podCIDR, bridgeName, gatewayIP, controlPlaneURL string) (*Agent, error) {
	return &Agent{
		NodeID:  nodeID,
		NodeIP:  nodeIP,
		PodCIDR: podCIDR,
		Bridge: Bridge{
			Name:      bridgeName,
			GatewayIP: gatewayIP,
		},
		ControlPlaneURL: controlPlaneURL,
		Services:        make(map[string]*Service),
		allocated:       map[string]bool{},

		RegistryPath:      filepath.Join(DataDir, "registry"),
		SecretManagerPath: filepath.Join(DataDir, "secrets"),
		PodsPath:          filepath.Join(DataDir, "pods"),
	}, nil
}

func (a *Agent) InitNodeSetup() error {
	//0. Creating registry, secrets and pods directories
	// secrets is only readable by root, the agent runs as root anyway
	if err := os.MkdirAll(a.RegistryPath, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(a.SecretManagerPath, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(a.PodsPath, 0755); err != nil {
		return err
	}

	//1. Loading br_netfilter so bridged traffic goes through iptables
	if err := run("modprobe", "br_netfilter"); err != nil {
		return err
	}

	//2. Enabling IP forwarding and iptables on bridge
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	if err := run("sysctl", "-w", "net.bridge.bridge-nf-call-iptables=1"); err != nil {
		return err
	}

	//3. Setting up bridge
	if err := runIgnoreExists("ip", "link", "add", "name", a.Bridge.Name, "type", "bridge"); err != nil {
		return err
	}
	if err := runIgnoreExists("ip", "addr", "add", a.Bridge.GatewayIP, "dev", a.Bridge.Name); err != nil {
		return err
	}
	if err := run("ip", "link", "set", a.Bridge.Name, "up"); err != nil {
		return err
	}

	//4. Creating KUBE chains
	if err := runIgnoreExists("iptables", "-t", "nat", "-N", "KUBE-SERVICES"); err != nil {
		return err
	}
	if err := runIgnoreExists("iptables", "-t", "nat", "-N", "KUBE-POSTROUTING"); err != nil {
		return err
	}
	if err := runIgnoreExists("iptables", "-t", "filter", "-N", "KUBE-FORWARD"); err != nil {
		return err
	}

	//5. Jumping from built-in chains to KUBE chains
	if err := ensureJump("nat", "PREROUTING", "KUBE-SERVICES"); err != nil {
		return err
	}
	if err := ensureJump("nat", "OUTPUT", "KUBE-SERVICES"); err != nil {
		return err
	}
	if err := ensureJump("nat", "POSTROUTING", "KUBE-POSTROUTING"); err != nil {
		return err
	}
	if err := ensureJump("filter", "FORWARD", "KUBE-FORWARD"); err != nil {
		return err
	}

	//6. Masquerading pod traffic leaving the pod CIDR
	// KUBE-POSTROUTING is written by us only, so flushing it first keeps the rule
	// from stacking on restart and drops rules left over from an older PodCIDR
	if err := run("iptables", "-t", "nat", "-F", "KUBE-POSTROUTING"); err != nil {
		return err
	}
	if err := run("iptables", "-t", "nat", "-A", "KUBE-POSTROUTING", "-s", a.PodCIDR, "!", "-d", a.PodCIDR, "-j", "MASQUERADE"); err != nil {
		return err
	}

	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, out)
	}
	return nil
}

// ensureJump inserts a jump into a built-in chain only when it is not there yet,
// because -I always inserts and would stack one more copy on every restart
func ensureJump(table, builtinChain, kubeChain string) error {
	// iptables -C exits 0 when the rule already exists
	if err := run("iptables", "-t", table, "-C", builtinChain, "-j", kubeChain); err == nil {
		return nil
	}
	return run("iptables", "-t", table, "-I", builtinChain, "1", "-j", kubeChain)
}

// ensureRule appends a rule to a chain only when it is not there yet,
// because -A always appends and would stack one more copy on every restart
func ensureRule(table, chain string, rule ...string) error {
	// iptables -C exits 0 when the rule already exists
	checkArgs := append([]string{"-t", table, "-C", chain}, rule...)
	if err := run("iptables", checkArgs...); err == nil {
		return nil
	}
	appendArgs := append([]string{"-t", table, "-A", chain}, rule...)
	return run("iptables", appendArgs...)
}

// runIgnoreExists runs a create command and swallows only the "already there" error,
// so restarting the agent on an already initialised node is not treated as a failure
func runIgnoreExists(name string, args ...string) error {
	err := run(name, args...)
	if err == nil {
		return nil
	}
	message := err.Error()
	// iptables -N: "Chain already exists"; ip link/addr add: "RTNETLINK answers: File exists"
	if strings.Contains(message, "already exists") || strings.Contains(message, "File exists") {
		return nil
	}
	return err
}

// helper we use to return IPs inside a NODE private net
// Valid IPs (for PodCIDR 10.244.1.0/24): 10.244.1.2 - 10.244.1.254 (253 IPs)
// Reserved: 10.244.1.0 (network), 10.244.1.1 (gateway/bridge), 10.244.1.255 (broadcast)
func (a *Agent) GetNextIP() (string, error) {
	_, podNetwork, err := net.ParseCIDR(a.PodCIDR)
	if err != nil {
		return "", err
	}
	base := podNetwork.IP.To4()
	if base == nil {
		return "", fmt.Errorf("solo IPv4: %s", a.PodCIDR)
	}

	ones, bits := podNetwork.Mask.Size()
	max := 1<<(bits-ones) - 1 // .255 en un /24

	for offset := 2; offset < max; offset++ {
		ip := make(net.IP, 4)
		copy(ip, base)
		v := binary.BigEndian.Uint32(ip) + uint32(offset)
		binary.BigEndian.PutUint32(ip, v)

		s := ip.String()
		if !a.allocated[s] {
			a.allocated[s] = true
			return s, nil
		}
	}
	return "", fmt.Errorf("sin IPs libres en %s", a.PodCIDR)
}
func (a *Agent) ReleaseIP(releasedIP string) error {
	ip, ok := a.allocated[releasedIP]
	if !ip || !ok {
		return fmt.Errorf("Ip already released!")
	}
	a.allocated[releasedIP] = false
	return nil
}

// ShutdownNode drains the node: every pod gets SIGTERM and, after the grace time, SIGKILL
// It is not called when the agent stops, only for an explicit drain
func (a *Agent) ShutdownNode(ctx context.Context) error {
	//TODO get error
	for _, service := range a.Services {
		go a.ShutdownPods(ctx, service)
	}
	return nil
}
