package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// podStateFile lives in every pod directory and is what lets a restarted agent find its pods again
const podStateFile = "pod.json"

// podState is the part of a Pod written to disk, enough to adopt the pod after an agent restart
type podState struct {
	ID          string `json:"id"`
	ServiceName string `json:"serviceName"`
	IP          string `json:"ip"`
	NetNS       string `json:"netns"`
	VethHost    string `json:"vethHost"`
	PID         int    `json:"pid"`
	// StartTime is the process start time in clock ticks since boot (/proc/<pid>/stat field 22)
	// PIDs get reused once a process dies, PID + start time identifies one process for good
	StartTime uint64    `json:"startTime"`
	CreatedAt time.Time `json:"createdAt"`
}

// savePodState writes <pod dir>/pod.json
// It goes through a temporary file and a rename, so a crash halfway never leaves a truncated JSON behind
func savePodState(pod *Pod) error {
	pid := pod.Process.Process.Pid
	startTime, err := processStartTime(pid)
	if err != nil {
		return err
	}

	state := podState{
		ID:          pod.ID,
		ServiceName: pod.ServiceName,
		IP:          pod.IP,
		NetNS:       pod.NetNS,
		VethHost:    pod.VethHost,
		PID:         pid,
		StartTime:   startTime,
		CreatedAt:   pod.CreatedAt,
	}
	stateJSON, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("pod %s state: %w", pod.ID, err)
	}

	statePath := filepath.Join(pod.DirPath, podStateFile)
	temporaryPath := statePath + ".tmp"
	if err := os.WriteFile(temporaryPath, stateJSON, 0644); err != nil {
		return fmt.Errorf("pod %s state: %w", pod.ID, err)
	}
	return os.Rename(temporaryPath, statePath)
}

// processStartTime reads the start time of a process from /proc/<pid>/stat
func processStartTime(pid int) (uint64, error) {
	statContent, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}

	// field 2 is the process name between parentheses and it may contain spaces or ')',
	// so fields are counted from the last ')' on
	nameEnd := bytes.LastIndexByte(statContent, ')')
	if nameEnd < 0 {
		return 0, fmt.Errorf("unexpected /proc/%d/stat format", pid)
	}
	fields := strings.Fields(string(statContent[nameEnd+1:]))

	// fields[0] is field 3 (state), so field 22 (starttime) is fields[19]
	const startTimeIndex = 22 - 3
	if len(fields) <= startTimeIndex {
		return 0, fmt.Errorf("unexpected /proc/%d/stat format", pid)
	}
	return strconv.ParseUint(fields[startTimeIndex], 10, 64)
}

// adoptedPollInterval is how often an adopted pod is checked for exit
// The agent is no longer its parent, so it cannot Wait for it and has to look at /proc instead
const adoptedPollInterval = time.Second

// AdoptPods scans the pod directories left by a previous run and takes back every pod
// whose process is still alive. It must run before any service or pod is created, so
// the IPs of adopted pods are already taken when the allocator hands out new ones.
// Adopted pods wait in a.adopted until their service is created again (see CreateService).
// Pods whose process is gone have their netns, endpoint chain and directory removed.
func (a *Agent) AdoptPods() error {
	entries, err := os.ReadDir(a.PodsPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		podDir := filepath.Join(a.PodsPath, entry.Name())

		state, err := loadPodState(podDir)
		if err != nil {
			// no pod.json: the pod never finished being created, there is no PID to look for
			fmt.Printf("skipping %s: %v\n", podDir, err)
			continue
		}

		if !processAlive(state.PID, state.StartTime) {
			fmt.Printf("pod %s is gone, cleaning it up\n", state.ID)
			cleanupDeadPod(state, podDir)
			continue
		}

		pod := adoptPod(state, podDir)
		a.allocated[pod.IP] = true
		a.adopted[pod.ServiceName] = append(a.adopted[pod.ServiceName], pod)
		fmt.Printf("pod %s adopted (pid %d)\n", pod.ID, state.PID)
	}
	return nil
}

func loadPodState(podDir string) (podState, error) {
	var state podState
	stateJSON, err := os.ReadFile(filepath.Join(podDir, podStateFile))
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(stateJSON, &state); err != nil {
		return state, fmt.Errorf("%s: %w", podStateFile, err)
	}
	return state, nil
}

// processAlive tells whether the process that was written to pod.json is still running
// The start time check catches a dead pod whose PID now belongs to someone else
func processAlive(pid int, startTime uint64) bool {
	currentStartTime, err := processStartTime(pid)
	return err == nil && currentStartTime == startTime
}

// adoptPod rebuilds the in-memory Pod from its state file
func adoptPod(state podState, podDir string) *Pod {
	// FindProcess never fails on Linux, it only wraps the PID so Signal works as before
	process, _ := os.FindProcess(state.PID)
	exited := make(chan struct{})
	go watchAdoptedProcess(state.PID, state.StartTime, exited)

	return &Pod{
		ID:          state.ID,
		ServiceName: state.ServiceName,
		IP:          state.IP,
		NetNS:       state.NetNS,
		VethHost:    state.VethHost,
		Status:      StatusRunning,
		CreatedAt:   state.CreatedAt,
		DirPath:     podDir,
		Process: Process{
			PID:     strconv.Itoa(state.PID),
			Process: process,
			Exited:  exited,
		},
	}
}

// watchAdoptedProcess closes exited once the process is gone, the same contract the
// Wait goroutine of SetupProcess has, so shutdown and remove work the same for both
func watchAdoptedProcess(pid int, startTime uint64, exited chan struct{}) {
	ticker := time.NewTicker(adoptedPollInterval)
	defer ticker.Stop()
	for range ticker.C {
		if !processAlive(pid, startTime) {
			close(exited)
			return
		}
	}
}

// cleanupDeadPod removes what a dead pod left behind. Every step is best effort:
// whatever is already gone is fine, and nothing here should stop the agent from starting
func cleanupDeadPod(state podState, podDir string) {
	// deleting the netns removes eth0 inside it, and with it the host end of the veth pair
	run("ip", "netns", "del", state.NetNS)
	run("ip", "link", "del", state.VethHost)
	// -X fails while the service chain from the previous run still jumps to it; flushing it
	// at least makes that jump fall through instead of sending traffic to a dead pod
	run("iptables", "-t", "nat", "-F", state.ID)
	run("iptables", "-t", "nat", "-X", state.ID)
	os.RemoveAll(podDir)
}
