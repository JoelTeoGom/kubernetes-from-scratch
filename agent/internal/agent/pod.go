package agent

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// KUBE-SVC-<service> balances ClusterIP traffic over local pods and remote nodes,
	// KUBE-EXT-<service> balances NodePort traffic over local pods only, and
	// KUBE-SEP-<service>-<n> is one endpoint chain per backend, so iptables -S tells them apart at a glance
	KubeServiceChainPrefix  = "KUBE-SVC"
	KubeExternalChainPrefix = "KUBE-EXT"
	KubeEndpointChainPrefix = "KUBE-SEP"
	PodGraceTime            = 10 * time.Second

	// podLogFile collects the pod stdout and stderr inside its directory
	podLogFile = "out.log"
)

type Pod struct {
	ID          string
	ServiceName string
	IP          string // 10.244.1.5
	NetNS       string // NetNS name
	VethHost    string // veth host peer
	Status      Status // pending | running | failed
	CreatedAt   time.Time
	Process     Process
	DirPath     string
}

type Process struct {
	PID     string
	Process *os.Process
	// Exited is closed once the process is gone, by the only goroutine that calls Wait
	Exited chan struct{}
}

type Status string

const (
	StatusPending Status = "PENDING"
	StatusRunning Status = "RUNNING"
	StatusFailed  Status = "FAILED"
)

func NewPod(id, serviceName, ip string) *Pod {
	return &Pod{
		ID:          id,
		ServiceName: serviceName,
		IP:          ip,
		NetNS:       id,
		Status:      StatusPending,
		CreatedAt:   time.Now(),
	}
}

// TODO(rollback): partial failures leave orphan state behind.
// The pod is only appended to LocalPods once everything succeeded, so the in-memory
// state stays clean, but the kernel state does not:
//   - SetupPodNetwork may fail halfway, leaving the netns and the veth pair behind.
//   - SetupPodIptables flushes the service chain first, so a failure after that point
//     leaves it empty: no REJECT rule and no backends, i.e. the service blackholes.
//
// Each step needs its undo, run in reverse order on error.
func (a *Agent) CreatePod(serviceName string) (pod *Pod, err error) {
	service, ok := a.Services[serviceName]
	if !ok || service == nil {
		return nil, fmt.Errorf("Service unavailable to create a pod!")
	}
	podIP, err := a.GetNextIP()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			a.ReleaseIP(podIP)
		}
	}()

	podID, err := service.GetNextPodID()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			service.ReleaseID(podID)
		}
	}()

	pod = NewPod(podID, serviceName, podIP)

	//KUBELET FUNCTIONS
	//1.setting up netns
	if err = a.SetupPodNetwork(pod); err != nil {
		return nil, err
	}

	//2.Starting the process
	if err = a.SetupProcess(pod); err != nil {
		return nil, err
	}

	//KUBE-PROXY FUNCTIONS
	//3.setting up ip table rules for the pod
	if err = service.SetupPodIptables(pod); err != nil {
		return nil, err
	}

	//4. Writing pod.json so a restarted agent can adopt the pod
	// The pod is already serving traffic, so a failure here is not worth tearing it down:
	// it only means this pod will not be adopted after a restart
	if stateErr := savePodState(pod); stateErr != nil {
		fmt.Printf("pod %s will not survive an agent restart: %v\n", pod.ID, stateErr)
	}

	service.LocalPods = append(service.LocalPods, pod)

	return pod, nil
}

// SetupProcess prepares the pod directory and starts the pod binary inside the pod netns
//  1. <PodsPath>/<podID> is created
//  2. the binary and the env file are copied from the registry and the secrets directory
//  3. the binary is started with ip netns exec, from the pod directory so it finds env.local
func (a *Agent) SetupProcess(pod *Pod) error {
	//1. Check or create Pod directory
	dir := filepath.Join(a.PodsPath, pod.ID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("pod %s directory: %w", pod.ID, err)
	}
	pod.DirPath = dir

	//2. Copying binary + env file to the pod directory
	// cp keeps the exec bit of the binary
	if err := run("cp", filepath.Join(a.RegistryPath, "main"), dir); err != nil {
		return err
	}
	if err := run("cp", filepath.Join(a.SecretManagerPath, "env.local"), dir); err != nil {
		return err
	}

	//3. Executing the binary inside the pod netns
	// ip netns exec joins the netns and then execs the binary, so the PID we get is the binary's
	cmd := exec.Command("ip", "netns", "exec", pod.NetNS, filepath.Join(dir, "main"))
	cmd.Dir = dir

	// The pod must outlive the agent:
	//   - its own session, so a Ctrl-C or a signal sent to the agent process group never reaches it
	//   - its output goes to a file it owns, not to the agent stdout, which would vanish (or SIGPIPE
	//     the pod) once the agent is gone
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	logFile, err := os.OpenFile(filepath.Join(dir, podLogFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("pod %s log file: %w", pod.ID, err)
	}
	// the child gets its own copy of the descriptor on Start, the agent does not need it afterwards
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Start does not block, the process keeps running after SetupProcess returns
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("pod %s start: %w", pod.ID, err)
	}
	pod.Status = StatusRunning

	exited := make(chan struct{})
	pod.Process = Process{
		PID:     strconv.Itoa(cmd.Process.Pid),
		Process: cmd.Process,
		Exited:  exited,
	}

	// Wait can only be called once per process, so this goroutine owns it (and reaps the zombie)
	// while shutdown, remove and health checks just listen on Exited
	go func() {
		cmd.Wait()
		close(exited)
	}()

	return nil
}

// SetupPodIptables creates the new pod endpoint chain and rewrites both service chains with it
//   - KUBE-SVC (ClusterIP): local pods + remote nodes, this is where a call can leave the node
//   - KUBE-EXT (NodePort): local pods only. Whoever reaches NodeIP:NodePort already picked this
//     node, so sending it on to another node would only bounce the packet between nodes
func (s *Service) SetupPodIptables(pod *Pod) error {
	newBackend := Backend{ID: pod.ID, IP: pod.IP, Port: s.PodPort}

	return s.writeChains(append(s.Backends(), newBackend), append(s.LocalBackends(), newBackend))
}

// writeChains makes sure every backend has its endpoint chain (remote nodes included) and
// then rewrites both service chains. Endpoint chains go first, so a failure there leaves the
// current service rules untouched
func (s *Service) writeChains(clusterBackends, localBackends []Backend) error {
	// localBackends is a subset of clusterBackends, so this covers every endpoint chain
	for _, backend := range clusterBackends {
		if err := ensureEndpointChain(backend); err != nil {
			return err
		}
	}

	if err := writeBalancingChain(s.ServiceChain(), clusterBackends); err != nil {
		return err
	}
	return writeBalancingChain(s.ExternalChain(), localBackends)
}

// writeBalancingChain flushes the chain and spreads tcp traffic evenly over the backends
// Probabilities are 1/n, 1/(n-1), ..., and the last rule has no probability so it takes whatever is left
// With no backends it rejects, so a client fails right away instead of waiting for a timeout
func writeBalancingChain(chain string, backends []Backend) error {
	if err := run("iptables", "-t", "nat", "-F", chain); err != nil {
		return err
	}

	backendCount := len(backends)
	if backendCount == 0 {
		return run("iptables", "-t", "nat", "-A", chain, "-j", "REJECT", "--reject-with", "icmp-port-unreachable")
	}

	for backendIndex, backend := range backends {
		var err error
		if backendIndex == backendCount-1 {
			err = run("iptables", "-t", "nat", "-A", chain, "-p", "tcp", "-j", backend.ID)
		} else {
			probability := 1.0 / float64(backendCount-backendIndex)
			err = run("iptables", "-t", "nat", "-A", chain, "-p", "tcp",
				"-m", "statistic", "--mode", "random",
				"--probability", fmt.Sprintf("%.5f", probability), "-j", backend.ID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ensureEndpointChain leaves the backend KUBE-SEP chain with exactly one DNAT to IP:Port
// It is created if missing and flushed otherwise, so it also fixes a chain left behind
// by a crash or pointing to an old address
func ensureEndpointChain(backend Backend) error {
	if err := runIgnoreExists("iptables", "-t", "nat", "-N", backend.ID); err != nil {
		return err
	}
	if err := run("iptables", "-t", "nat", "-F", backend.ID); err != nil {
		return err
	}
	return run("iptables", "-t", "nat", "-A", backend.ID, "-p", "tcp", "-j", "DNAT",
		"--to-destination", fmt.Sprintf("%s:%s", backend.IP, backend.Port))
}

// SetupPodNetwork creates the pod netns, wires it to the node bridge with a veth pair and configures IP + default route
func (a *Agent) SetupPodNetwork(pod *Pod) error {
	_, podNetwork, err := net.ParseCIDR(a.PodCIDR)
	if err != nil {
		return fmt.Errorf("invalid pod CIDR %q: %w", a.PodCIDR, err)
	}
	maskOnes, _ := podNetwork.Mask.Size()
	gatewayIP := strings.Split(a.Bridge.GatewayIP, "/")[0]

	vethHost, vethPod := vethNames(pod.ID)

	//2. Creating pod network namespace (same name as pod ID)
	if err := run("ip", "netns", "add", pod.NetNS); err != nil {
		return err
	}

	//3. Creating veth pair (one cable, two ends)
	if err := run("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethPod); err != nil {
		return err
	}

	//4. Moving pod end into the netns and renaming it to eth0
	if err := run("ip", "link", "set", vethPod, "netns", pod.NetNS); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", pod.NetNS, "ip", "link", "set", vethPod, "name", "eth0"); err != nil {
		return err
	}

	//5-6. Plugging host end into the bridge
	if err := run("ip", "link", "set", vethHost, "master", a.Bridge.Name); err != nil {
		return err
	}
	if err := run("ip", "link", "set", vethHost, "up"); err != nil {
		return err
	}

	//7. Configuring network inside the netns
	if err := run("ip", "netns", "exec", pod.NetNS, "ip", "addr", "add",
		fmt.Sprintf("%s/%d", pod.IP, maskOnes), "dev", "eth0"); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", pod.NetNS, "ip", "link", "set", "eth0", "up"); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", pod.NetNS, "ip", "link", "set", "lo", "up"); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", pod.NetNS, "ip", "route", "add", "default", "via", gatewayIP); err != nil {
		return err
	}

	pod.VethHost = vethHost
	return nil
}

// vethNames returns short interface names derived from the pod ID
// Linux interface names are limited to 15 chars, so "veth" + podID would overflow
func vethNames(podID string) (string, string) {
	hasher := fnv.New32a()
	hasher.Write([]byte(podID))
	podHash := fmt.Sprintf("%08x", hasher.Sum32())
	return "veth" + podHash, "eth0" + podHash
}

// RemovePod tears a pod down and gives back everything CreatePod took, in this order:
//  1. out of the service: dropped from LocalPods and both service chains rewritten, so no new
//     connection reaches a pod that is shutting down (with no pods left the chains REJECT)
//  2. process stopped: SIGTERM, grace time, SIGKILL
//  3. netns, veth, endpoint chain and pod directory removed, pod.json included, so the next
//     agent start does not find it
//  4. pod IP and pod ID released for the next pod
func (a *Agent) RemovePod(ctx context.Context, pod *Pod) error {
	service, ok := a.Services[pod.ServiceName]
	if ok {
		service.removeLocalPod(pod.ID)
		if err := service.writeChains(service.Backends(), service.LocalBackends()); err != nil {
			return err
		}
	}

	if err := stopProcess(ctx, pod); err != nil {
		return err
	}

	removePodResources(pod.ID, pod.NetNS, pod.VethHost, pod.DirPath)

	if err := a.ReleaseIP(pod.IP); err != nil {
		fmt.Println(err)
	}
	if ok {
		if err := service.ReleaseID(pod.ID); err != nil {
			fmt.Println(err)
		}
	}
	return nil
}

// removeLocalPod drops a pod from LocalPods, keeping the order of the others
func (s *Service) removeLocalPod(podID string) {
	for index, localPod := range s.LocalPods {
		if localPod.ID == podID {
			s.LocalPods = append(s.LocalPods[:index], s.LocalPods[index+1:]...)
			return
		}
	}
}

// removePodResources deletes what a pod leaves in the kernel and on disk. Every step is
// best effort: whatever is already gone is fine
func removePodResources(podID, netns, vethHost, podDir string) {
	// deleting the netns removes eth0 inside it, and with it the host end of the veth pair
	run("ip", "netns", "del", netns)
	run("ip", "link", "del", vethHost)
	// -X only works once no service chain jumps to it anymore
	run("iptables", "-t", "nat", "-F", podID)
	run("iptables", "-t", "nat", "-X", podID)
	if podDir != "" {
		os.RemoveAll(podDir)
	}
}

func (n *Agent) CheckPodHealth(pod *Pod) (Status, error) {
	//PATCH contra pod para ver current STATUS
	return "", nil
}

func (a *Agent) ShutdownPod(ctx context.Context, pod *Pod) error {
	if err := stopProcess(ctx, pod); err != nil {
		return err
	}

	// the process is confirmed dead here, whichever way it went
	err := a.ReleaseIP(pod.IP)
	if err != nil {
		fmt.Println(err)
	}
	return nil
}

// stopProcess sends SIGTERM and waits for the pod to exit, with SIGKILL after the grace time
// It returns once the process is confirmed dead
func stopProcess(ctx context.Context, pod *Pod) error {
	// a pod that already died is not an error, Exited is (or is about to be) closed
	err := pod.Process.Process.Signal(syscall.SIGTERM)
	if err != nil && !errors.Is(err, os.ErrProcessDone) {
		fmt.Println(err)
		return err
	}

	//10 sec grace time, cut short if ctx runs out first
	waitCtx, cancel := context.WithTimeout(ctx, PodGraceTime)
	defer cancel()

	select {
	case <-pod.Process.Exited:
		// the pod handled SIGTERM and exited on its own
	case <-waitCtx.Done():
		// the pod may exit right between the timeout and the kill, that is not an error
		err = pod.Process.Process.Signal(syscall.SIGKILL)
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			fmt.Println(err)
			return err
		}
		// SIGKILL cannot be ignored, so this wait is short
		<-pod.Process.Exited
	}
	return nil
}
