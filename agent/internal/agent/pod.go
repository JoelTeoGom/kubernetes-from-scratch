package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// KUBE-SVC-<service> holds the load balancing rules, KUBE-SEP-<service>-<n> is one
	// endpoint chain per pod, so iptables -S tells them apart at a glance
	KubeServiceChainPrefix  = "KUBE-SVC"
	KubeEndpointChainPrefix = "KUBE-SEP"
	PodGraceTime            = 10 * time.Second
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

	kubeService := fmt.Sprintf("%s-%s", KubeServiceChainPrefix, serviceName)

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
	if err = service.SetupPodIptables(kubeService, pod); err != nil {
		return nil, err
	}

	service.LocalPods = append(service.LocalPods, pod)

	return pod, nil
}

func (a *Agent) SetupProcess(pod *Pod) error {
	//1. Check or create Pod directory
	//2. Move binary + env file to directory
	//3. Execute binary +

	dir := fmt.Sprintf("/Pods/%s", pod.ID)
	err := os.MkdirAll(dir, 0777)
	if err != nil {
		panic(err)
	}
	pod.DirPath = dir

	registryPath := fmt.Sprintf("%s/main", a.RegistryPath)
	cmd := exec.Command("cp", registryPath, dir)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("cp failed : %v — %s", err, stderr.String())
	}

	secretPath := fmt.Sprintf("%s/env.local", a.SecretManagerPath)
	cmd = exec.Command("cp", secretPath, dir)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("cp failed: %v — %s", err, stderr.String())
	}

	binaryPath := fmt.Sprintf("../%s/main", pod.ID)
	cmd = exec.Command(binaryPath)

	// Without this, the child's output is discarded (sent to /dev/null)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Opción B: no bloqueante
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("PID:", cmd.Process.Pid)

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

// SetupPodIptables creates the new pod endpoint chain and rewrites the service chain with a jump to every backend
// Probabilities are 1/n, 1/(n-1), ..., and the last rule has no probability so it takes whatever is left
func (s *Service) SetupPodIptables(kubeService string, pod *Pod) error {

	//1. Creating Backends
	backends := s.Backends()
	backends = append(backends, Backend{ID: pod.ID, IP: pod.IP, Port: s.PodPort})
	backendCount := len(backends)

	//2. Making sure every backend has its endpoint chain (remote nodes included) before
	// touching the service chain, so a failure here leaves the current rules untouched
	for _, backend := range backends {
		if err := ensureEndpointChain(backend); err != nil {
			return err
		}
	}

	//3. Flushing service chain, it is rewritten entirely because probabilities change
	if err := run("iptables", "-t", "nat", "-F", kubeService); err != nil {
		return err
	}

	//4. Jumping from service chain to every backend
	for backendIndex, backend := range backends {
		var err error
		if backendIndex == backendCount-1 {
			err = run("iptables", "-t", "nat", "-A", kubeService, "-p", "tcp", "-j", backend.ID)
		} else {
			probability := 1.0 / float64(backendCount-backendIndex)
			err = run("iptables", "-t", "nat", "-A", kubeService, "-p", "tcp",
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

// TODO(removepod): tearing a pod down must give its resources back, otherwise they
// leak exactly like a failed create would: ReleaseIP for the pod IP, ReleaseID on the
// service for the pod ID, delete the netns and the veth, drop its KUBE-SEP chain and
// rewrite the service chain so the probabilities match the remaining backends
func (a *Agent) RemovePod(pod *Pod) (*Pod, error) {
	err := pod.Process.Process.Signal(syscall.SIGTERM)
	if err != nil {
		fmt.Println(err)
		return pod, err
	}
	//10 sec grace time
	waitCtx, cancel := context.WithTimeout(context.Background(), PodGraceTime)
	defer cancel()
loop:
	for {
		select {
		case <-waitCtx.Done():
			err = a.ReleaseIP(pod.IP)
			if err != nil {
				fmt.Println(err)
			}
			err = pod.Process.Process.Signal(syscall.SIGKILL)
			if err != nil {
				fmt.Println(err)
				return pod, err
			}
			break loop
		}
	}

	//TODO REMOVE FROM SERVICE LOCAL POD LIST

	return pod, nil
}

func (n *Agent) CheckPodHealth(pod *Pod) (Status, error) {
	//PATCH contra pod para ver current STATUS
	return "", nil
}

func (a *Agent) ShutdownPod(ctx context.Context, pod *Pod) error {
	//Signal sigterm
	err := pod.Process.Process.Signal(syscall.SIGTERM)
	if err != nil {
		fmt.Println(err)
		return err
	}

	//10 sec grace time, cut short if the node shutdown ctx runs out first
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

	// the process is confirmed dead here, whichever way it went
	err = a.ReleaseIP(pod.IP)
	if err != nil {
		fmt.Println(err)
	}
	return nil
}
func (p *Pod) CreatePodContainer()
