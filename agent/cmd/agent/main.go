package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/JoelTeoGom/kubernetes-from-scratch/agent/internal/agent"
	"github.com/JoelTeoGom/kubernetes-from-scratch/agent/internal/apiclient"
	"github.com/JoelTeoGom/kubernetes-from-scratch/agent/internal/config"
	"github.com/JoelTeoGom/kubernetes-from-scratch/agent/internal/event"
	"github.com/JoelTeoGom/kubernetes-from-scratch/agent/internal/network"
	"github.com/JoelTeoGom/kubernetes-from-scratch/agent/internal/reconcile"
)

func main() {
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	//configs
	cfg := config.NewConfig()

	//obtain Network variables
	localIP, err := network.ObtainOutboundIP()
	if err != nil {
		panic(err)
	}
	hostname, err := network.ResolveHostname()
	if err != nil {
		panic(err)
	}
	//PodCIDR, gateway and bridge are derived from the node number at the end of the hostname (node-1)
	nodeNetwork, err := network.NodeNetworkFromHostname(hostname)
	if err != nil {
		panic(err)
	}

	eventJobs := make(chan event.Event)
	defer close(eventJobs)

	//Create Node and setup ip table rules
	node, err := agent.NewAgent(hostname, localIP, nodeNetwork.PodCIDR, nodeNetwork.BridgeName, nodeNetwork.GatewayIP, cfg.ControlPlaneURL())
	if err != nil {
		panic(err)
	}
	if err := node.InitNodeSetup(); err != nil {
		panic(err)
	}

	//Adopt pods left running by a previous agent before creating anything, so their IPs and
	//IDs are taken and their services point to them again once they are created
	if err := node.AdoptPods(); err != nil {
		panic(err)
	}

	cp := apiclient.NewAPIClient(node, eventJobs)

	//0. Register CP
	err = cp.RegisterNode(ctx)
	if err != nil {
		panic(err)
	}
	// 1. List (services and pods)
	err = cp.List(ctx)
	if err != nil {
		fmt.Println(err)
	}

	// 3. Create Agent Reconciler to Listen ControlPlane Events and Process (ex: Create pod, service, health...)
	go reconcile.StartReconciler(ctx, node, eventJobs)

	// 4. watch future events
	err = cp.Watch(ctx)
	if err != nil {
		fmt.Println(err)
	}

	<-ctx.Done()

	// Stopping the agent is not draining the node: pods, netns and iptables rules stay as
	// they are, so traffic keeps flowing while the agent restarts and adopts them again.
	// Killing the pods (node.ShutdownNode) is left for an explicit drain order from the control plane
	fmt.Println("agent stopped, pods left running")
}
