package agent

import (
	"context"
	"fmt"
	"strconv"
)

type Service struct {
	Name string

	ClusterIP   string
	ClusterPort string //the une used combined with Cluster IP

	PodPort string //the one that we use inside PODs (maybe we need it to curl)  HEALTH ISSUES

	NodePort string //The one combined with NodeIP:NodePort used to identify remote SERVICE

	LocalPods      []*Pod
	RemoteBackends []Backend //NODES that have available pods (THIS service pods)

	//pod IDs already handed out for this service, same idea as Agent.allocated for IPs
	//a released ID goes back to false so the index can be reused without shifting the others
	takenIDs map[string]bool
}

// Backend is one destination of the service chain
// ID is also the name of its KUBE-SEP endpoint chain, which DNATs to IP:Port
// (pod IP + pod port for a local pod, node IP + node port for a remote node)
type Backend struct {
	ID   string
	IP   string
	Port string
}

// NewRemoteBackend builds the backend for another node serving this service
// The node ID goes in the chain name so it never collides with a local pod index
func NewRemoteBackend(serviceName, nodeID, nodeIP, nodePort string) Backend {
	return Backend{
		ID:   fmt.Sprintf("%s-%s-%s", KubeEndpointChainPrefix, serviceName, nodeID),
		IP:   nodeIP,
		Port: nodePort,
	}
}

func NewService(name, clusterIP, clusterPort, nodePort, podPort string) *Service {
	return &Service{
		Name:           name,
		ClusterIP:      clusterIP,
		ClusterPort:    clusterPort,
		PodPort:        podPort,
		NodePort:       nodePort,
		LocalPods:      []*Pod{},
		RemoteBackends: []Backend{},
		takenIDs:       map[string]bool{},
	}
}

// NodePort range the control plane must respect, same one Kubernetes uses
const (
	nodePortMin = 30000
	nodePortMax = 32767
)

// parsePort rejects anything that is not a usable TCP port
// The payload reaches the agent as plain text from another process, so it is validated
// here as well even when the control plane already checked it
func parsePort(port string) (int, error) {
	number, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("port %q is not a number: %w", port, err)
	}
	if number < 1 || number > 65535 {
		return 0, fmt.Errorf("port %d is out of range 1-65535", number)
	}
	return number, nil
}

// parseNodePort also checks the port falls inside the NodePort range
func parseNodePort(port string) (int, error) {
	number, err := parsePort(port)
	if err != nil {
		return 0, err
	}
	if number < nodePortMin || number > nodePortMax {
		return 0, fmt.Errorf("node port %d is out of range %d-%d", number, nodePortMin, nodePortMax)
	}
	return number, nil
}

func (n *Agent) CreateService(name, clusterIP, clusterPort, nodePort, podPort string) (*Service, error) {
	if service, ok := n.Services[name]; ok {
		return service, nil
	}

	if _, err := parsePort(clusterPort); err != nil {
		return nil, fmt.Errorf("service %s cluster port: %w", name, err)
	}
	if _, err := parsePort(podPort); err != nil {
		return nil, fmt.Errorf("service %s pod port: %w", name, err)
	}
	if _, err := parseNodePort(nodePort); err != nil {
		return nil, fmt.Errorf("service %s node port: %w", name, err)
	}

	newService := NewService(name, clusterIP, clusterPort, nodePort, podPort)

	// pods of this service that survived an agent restart go back in before the rules
	// are written, so the service chains point to them from the start
	for _, adoptedPod := range n.adopted[name] {
		newService.takenIDs[adoptedPod.ID] = true
		newService.LocalPods = append(newService.LocalPods, adoptedPod)
	}

	// registered only once the rules are in place, so a half set up service never
	// ends up in the map for CreatePod to trip over
	if err := newService.CreateServiceSetup(name, n.NodeIP); err != nil {
		return nil, err
	}
	n.Services[name] = newService
	delete(n.adopted, name)

	return newService, nil
}

// ServiceChain is the chain ClusterIP traffic lands in (local pods + remote nodes)
func (s *Service) ServiceChain() string {
	return fmt.Sprintf("%s-%s", KubeServiceChainPrefix, s.Name)
}

// ExternalChain is the chain NodePort traffic lands in (local pods only)
func (s *Service) ExternalChain() string {
	return fmt.Sprintf("%s-%s", KubeExternalChainPrefix, s.Name)
}

func (s *Service) CreateServiceSetup(name, nodeIP string) error {
	//1. Creating service chains
	for _, chain := range []string{s.ServiceChain(), s.ExternalChain()} {
		if err := runIgnoreExists("iptables", "-t", "nat", "-N", chain); err != nil {
			return err
		}
	}

	//2. Jumping from KUBE-SERVICES to service chains
	// ClusterIP may be served by any node, NodePort only by this node's pods
	// /32 is what iptables assumes for a bare host address, spelled out so the rule
	// reads the same here as it does in iptables -S
	if err := ensureRule("nat", "KUBE-SERVICES", "-d", s.ClusterIP+"/32", "-p", "tcp", "--dport", s.ClusterPort, "-j", s.ServiceChain()); err != nil {
		return err
	}

	if err := ensureRule("nat", "KUBE-SERVICES", "-d", nodeIP+"/32", "-p", "tcp", "--dport", s.NodePort, "-j", s.ExternalChain()); err != nil {
		return err
	}

	//3. Pointing the service chains to the pods it already has
	// After an agent restart these are the adopted pods, which keep serving traffic.
	// With no pods yet, an empty backend list writes a single REJECT rule
	return s.writeChains(s.Backends(), s.LocalBackends())
}

// GetNextPodID returns the lowest free pod ID for this service and marks it as taken
// Scanning a map instead of using len(LocalPods) keeps IDs stable when a pod in the
// middle is removed, the same reason Agent.GetNextIP scans instead of counting
func (s *Service) GetNextPodID() (string, error) {
	// with n IDs known, index n is free at worst, so the scan always terminates
	for index := 0; index <= len(s.takenIDs); index++ {
		podID := fmt.Sprintf("%s-%s-%d", KubeEndpointChainPrefix, s.Name, index)
		if !s.takenIDs[podID] {
			s.takenIDs[podID] = true
			return podID, nil
		}
	}
	return "", fmt.Errorf("no free pod ID for service %s", s.Name)
}

// ReleaseID gives a pod ID back so a later pod can reuse the index
func (s *Service) ReleaseID(releasedID string) error {
	if !s.takenIDs[releasedID] {
		return fmt.Errorf("pod ID %s already released", releasedID)
	}
	s.takenIDs[releasedID] = false
	return nil
}

// LocalBackends returns only the pods running on this node
func (s *Service) LocalBackends() []Backend {
	var backends []Backend
	for _, pod := range s.LocalPods {
		backends = append(backends, Backend{ID: pod.ID, IP: pod.IP, Port: s.PodPort})
	}
	return backends
}

// Backends returns local pods first and then remote nodes that also serve this service
func (s *Service) Backends() []Backend {
	return append(s.LocalBackends(), s.RemoteBackends...)
}

func (a *Agent) ShutdownPods(ctx context.Context, s *Service) error {
	//TODO no err handling
	for _, pod := range s.LocalPods {
		go a.ShutdownPod(ctx, pod)
	}
	//Pods will be erased from local pod slice anyways
	return nil
}
