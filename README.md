# orchard

> A toy Kubernetes, written by hand in Go: a control plane, node agents that build pod
> network namespaces and program iptables, and an L4 load balancer in front of it all.

**Status:** work in progress, and a learning project. Not something to run anywhere that
matters. See [Scope and honest limits](#scope-and-honest-limits).

---

## What this is

A miniature orchestrator, built by hand to understand how the real ones work. Nothing here
wraps an existing tool: the load balancer moves the bytes itself, the agent creates the
network namespaces itself, writes its own iptables rules, and the two talk over a protocol
of their own.

It started as an L4 load balancer. It grew. What the agent does today is, in Kubernetes
terms, **kubelet + kube-proxy**: pod lifecycle, IP allocation, veth pairs, a node bridge,
and a set of `KUBE-*` iptables chains that DNAT a virtual service address to a real pod.
The L4 load balancer survives as the component in front, the equivalent of a cloud
LoadBalancer sitting ahead of a cluster's NodePorts.

Two components, developed as if they were separate repositories, kept in one for
convenience:

- **`orchestrator/`** — the API server and the L4 load balancer. Tracks which nodes exist and how
  they are doing, dispatches events to agents, and forwards client TCP connections to a
  node.
- **`agent/`** — the node agent. Registers with the control plane, then creates services
  and pods locally: namespaces, veth pairs, IP allocation and iptables rules.

---

## How a packet gets to a pod

The interesting part of the project, and the reason it exists.

```
client ──▶ lb data plane ──▶ nodeIP:NodePort
                                   │
                            PREROUTING
                                   │
                            KUBE-SERVICES          -d clusterIP --dport → KUBE-SVC (local + remote)
                                   │               -d nodeIP   --dport → KUBE-EXT (local only)
                                   ▼
                            KUBE-SVC-<hash>        -m statistic --probability 1/n
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
            KUBE-SEP-<hash>  KUBE-SEP-<hash>  (remote node backend)
                    │
              DNAT podIP:podPort
                    │
                    ▼
              br0 ──▶ veth ──▶ pod netns eth0
```

Each pod lives in its own network namespace, joined to a node bridge by a veth pair, with
an address from the node's pod CIDR and a default route through the bridge. Each pod gets
an endpoint chain (`KUBE-SEP-*`) whose only job is the DNAT to that pod. The service chain
(`KUBE-SVC-*`) holds the load balancing itself: one `-m statistic` rule per backend with
probability `1/n`, `1/(n-1)`, …, and the last one unconditional.

Which means the actual packet-by-packet balancing inside a node is done by **the kernel**.
The agent's job is to compute the probabilities and keep the rules correct as pods come and
go. That is a control plane, not a data plane — the same split as the real thing.

### Chain names are hashed

iptables allows at most 28 characters per chain name, and a readable name like
`KUBE-SEP-payments-gateway-node-12` does not fit. So, like kube-proxy, every chain is a fixed
prefix plus the first 16 characters of the base32 SHA-256 of what it stands for, always 25
characters long. The readable part goes into a `-m comment` on each rule:

```
-A KUBE-SERVICES -d 10.96.0.10/32 -p tcp --dport 80 -m comment --comment "payments cluster IP" -j KUBE-SVC-344EV2L4O6WTAALC
-A KUBE-SVC-344EV2L4O6WTAALC -p tcp -m statistic --mode random --probability 0.50000 -m comment --comment payments-0 -j KUBE-SEP-26QISHB54PXAUUTJ
-A KUBE-SVC-344EV2L4O6WTAALC -p tcp -m comment --comment payments@node-2 -j KUBE-SEP-UWGBZ3MP4ZQEVOXT
```

| Chain | Hash of | Example |
|---|---|---|
| `KUBE-SVC-*` | service name | `payments` |
| `KUBE-EXT-*` | service name | `payments` |
| `KUBE-SEP-*`, local pod | pod ID, `<service>-<n>` | `payments-0` |
| `KUBE-SEP-*`, remote node | `<service>@<node>` | `payments@node-2` |

The rest of this README writes chains with readable names (`KUBE-SVC-payments`) to keep the
examples easy to follow.

### Balancing happens twice

The load balancer picks a **node**. That node's iptables rules pick a **pod**. Two
independent decisions. This mirrors a real cluster: an external load balancer spreads
traffic across nodes, and kube-proxy spreads it across pods inside each one.

### Two listeners, never one

The data plane and the control plane listen on different ports, and the distinction is
absolute: anything arriving on `:8080` is a client, anything on `:9000` is an agent. The
kernel demultiplexes by destination port for free, so the balancer never has to inspect a
payload to work out who is talking to it — which would break protocol-agnosticism and
deadlock against any protocol where the server speaks first.

### Every node owns a /24, but pod IPs stay local

Each node takes its own slice of `10.244.0.0/16`, derived from the number at the end of its
hostname: `node-1` gets `10.244.1.0/24`, bridge `br1` and gateway `10.244.1.1`. No address
coordination is needed, the hostname is enough.

Pod IPs are unique across the cluster, but there are no routes between the nodes' pod
ranges, so they never leave their node: a pod on another node is reached as
`nodeIP:NodePort`, never by its pod IP. Kubernetes adds those routes (or an overlay) to get
real pod-to-pod traffic across nodes; this project does not, and gets to skip the problem.

---

## Explaining how networking works in our environment

### The scenario

A cluster with three nodes and two services:

- **`payments`** has three pods, one on each node (`node-1`, `node-2`, `node-3`).
- **`users`** has a pod on `node-1`, and that pod wants to call `payments`.

`users` does not know where the `payments` pods are. It only knows the service's
`ClusterIP:ClusterPort`. Every connection should land on any of the three `payments` pods
with the same probability, whether that pod is on the local node or on another one.

Every node runs the same agent, so every node holds the same two chains per service:

```
KUBE-SERVICES
 ├─ ClusterIP:ClusterPort → KUBE-SVC-payments  (local pods + remote nodes)
 └─ NodeIP:NodePort       → KUBE-EXT-payments  (local pods only)
```

### Node 1, where the `users` pod runs

1. `users` opens a connection to `ClusterIP:ClusterPort` of `payments`. That address is not
   in its subnet, so the packet leaves through its default route: the gateway, which is the
   node 1 bridge.
2. `PREROUTING` → `KUBE-SERVICES`: the destination matches the ClusterIP, so the packet
   jumps to **`KUBE-SVC-payments`**.
3. `KUBE-SVC-payments` has one rule per backend, local pods first and remote nodes after:
   ```
   -m statistic --probability 0.33333 -j KUBE-SEP-payments-0        (local pod)
   -m statistic --probability 0.50000 -j KUBE-SEP-payments@node-2   (node 2)
                                      -j KUBE-SEP-payments@node-3   (node 3)
   ```
   Each backend ends up with 1/3: the first one takes 1/3, the second one 2/3 × 1/2 = 1/3,
   and the last one takes whatever is left.
4. Say node 3 wins. `KUBE-SEP-payments@node-3` does `DNAT → NodeIP3:NodePort`.
5. On the way out, `KUBE-POSTROUTING` sees a source inside the pod CIDR and a destination
   outside it, and applies `MASQUERADE`. The packet leaves with node 1's IP as its source.

### Node 3

6. The packet arrives at `NodeIP3:NodePort`. `KUBE-SERVICES` knows that port belongs to
   `payments` and jumps to **`KUBE-EXT-payments`**, which only holds node 3's local pods:
   ```
   -j KUBE-SEP-payments-0   → DNAT 10.244.3.x:PodPort
   ```
7. The packet reaches the `payments` pod on node 3.

### The way back

8. The pod replies to node 1. The reply goes through node 3's host, where conntrack undoes
   the DNAT. When it reaches node 1, conntrack undoes the masquerade and the DNAT, and
   `users` gets the reply as if it came from the ClusterIP.

### Notes

- **The draw happens once per connection.** Only the first packet of a connection goes
  through the `-m statistic` rules. Every packet after that follows the conntrack entry, so
  the whole TCP connection always stays on the same backend.
- **Why NodePort needs its own chain.** If the NodePort rule jumped to `KUBE-SVC-payments`,
  step 6 would draw again among local and remote backends, and node 3 could send the packet
  on to node 1 or node 2, bouncing it between nodes. `KUBE-EXT-payments` keeps it on node 3:
  whoever reaches `NodeIP:NodePort` already picked this node.
- **No masquerade mark needed.** Kubernetes marks traffic with `0x4000` (`KUBE-MARK-MASQ`)
  to masquerade it. Here that is not needed: traffic sent to a remote node always comes from
  a local pod, so the pod CIDR rule already masquerades it. Traffic arriving through a
  NodePort always goes to a local pod, so the reply comes back through the same host and
  conntrack can reverse it.
- **A node with no pods of a service rejects its NodePort.** `KUBE-EXT-<service>` is then a
  single `REJECT`. The control plane should only list a node as a remote backend when it has
  pods of that service.
- **Forwarding must be allowed.** Steps 1 and 7 cross the `FORWARD` chain, between the
  bridge and the network. If the `FORWARD` policy is `DROP` (Docker sets it that way), those
  packets are dropped unless `KUBE-FORWARD` accepts them.

---

## How a pod is run

There are no images and no container runtime. A pod is **a network namespace with a
process in it**, and the agent plays the part of kubelet and container runtime at once.

### On disk

Everything lives under `/var/lib/orchard` on each node:

```
/var/lib/orchard/
├── registry/main          — the binary every pod runs (our "image registry")
├── secrets/env.local      — the env file every pod gets (our "secret manager")
└── pods/
    └── payments-0/
        ├── main           — copy of the binary
        ├── env.local      — copy of the env file
        ├── out.log        — the pod's stdout and stderr
        └── pod.json       — what the agent needs to find the pod again
```

### Creating a pod

`CreatePod` runs three steps, in this order:

1. **Network** (`SetupPodNetwork`): create the netns, a veth pair, plug the host end into the
   node bridge, give the pod end an IP from the node's /24 and a default route through the
   bridge.
2. **Process** (`SetupProcess`): create the pod directory, copy the binary and the env file
   into it, and start the binary with `ip netns exec <netns> ./main` from that directory.
   `ip netns exec` joins the namespace and then execs the binary, so the PID the agent gets
   back is the pod's own.
3. **Traffic** (`SetupPodIptables`): only now the pod gets its `KUBE-SEP` chain and joins the
   service chains. Traffic is never sent to a pod whose process failed to start.

Then `pod.json` is written with the pod's ID, service, IP, netns, veth, PID and the process
start time.

### Pods outlive the agent

Stopping the agent is not draining the node. When the agent stops, pods keep running and
their iptables rules stay in place, so traffic keeps flowing while the agent is down. For
that, each pod is started:

- **in its own session** (`setsid`), so a Ctrl-C or a signal sent to the agent never reaches it;
- **writing to its own `out.log`**, not to the agent's stdout, which would disappear with the
  agent;
- under systemd, with **`KillMode=process`** (see
  [`agent/deploy/orchard-agent.service`](agent/deploy/orchard-agent.service)), so
  `systemctl restart` only signals the agent and not every process in its cgroup.

Killing every pod (`ShutdownNode`) is kept for an explicit drain.

### Adopting pods after a restart

A restarted agent has lost its in-memory state, and it is no longer the parent of its
pods. Kubernetes solves this with a shim process per container that the runtime can
reconnect to; here the truth is `pod.json` plus `/proc`:

1. Right after the node setup, and before creating anything, `AdoptPods` reads every
   `pods/*/pod.json`.
2. A pod counts as alive only if its PID exists **and** has the same start time
   (`/proc/<pid>/stat`, field 22). PIDs get reused, PID + start time does not.
3. Alive pods are adopted: their IP is marked as taken, and they wait until their service is
   created again. Then they go back into its `LocalPods` before its chains are written, so
   the service points to them from the start instead of rejecting traffic.
4. Dead pods are cleaned up: netns, veth, endpoint chain and directory.

An adopted pod is not a child of the agent, so the agent cannot `Wait` for it. It checks
`/proc` once a second instead, and loses the exit code.

---

## Scope and honest limits

This is a toy. It is meant to teach me Linux networking and how Kubernetes is put together,
and it is written by hand on purpose. Which means:

- **Linux only, and root only.** Network namespaces, veth pairs, bridges and iptables are
  Linux. The agent needs root or `CAP_NET_ADMIN`. The load balancer runs anywhere.
- **Virtual machines, not containers.** A "pod" here is a network namespace with a process
  in it. There is no image, no filesystem isolation, no cgroups.
- **The CRI and the CNI are hardcoded.** Kubernetes has pluggable interfaces precisely so
  that Docker, containerd, Calico or Cilium can each do this differently. Here there is one
  way of creating a namespace and one way of writing an iptables rule, both baked into the
  agent. That is the opposite of what a real orchestrator does, and it is deliberate: the
  point is to write the thing an interface would normally hide.
- **iptables rules are written directly**, by shelling out to `iptables` and `ip`. Real
  implementations use netlink. Running this alongside Docker on the same host is asking for
  trouble, because Docker has its own opinions about the same chains.
- **No declarative state yet.** The control plane dispatches imperative events. There is no
  desired state to reconcile against, which is the single biggest thing separating this
  from an orchestrator. It is on the roadmap. Until then, a restarted agent adopts the pods
  it finds alive, but nothing tells it whether the cluster still wants them, or wants more.

---

## Layout

```
orchard/
├── orchestrator/  — API server, node registry, L4 load balancer
├── agent/         — node agent: registration, IPAM, pod netns + veth, iptables rules
│   └── deploy/    — systemd unit for the agent
└── docs/          — notes and design write-ups
```

---

## Setting it up

Each piece runs on its own machine, all on the same LAN. A home router is enough.

### Requirements

- Go 1.25 or newer on every machine.
- Linux on every node that runs an agent. Pods live in network namespaces, which only
  exist on Linux, and the agent needs root (or `CAP_NET_ADMIN`) to create them.
- `iptables` and `iproute2` on every node, plus a kernel with the `br_netfilter` module.
  The agent loads it and sets `net.bridge.bridge-nf-call-iptables=1`, so that traffic
  crossing the node bridge is seen by iptables at all.
- **A node with Docker installed needs care.** Docker sets the `FORWARD` policy to `DROP`
  and manages its own chains in the same tables. Use a clean VM.
- The load balancer itself runs on any OS.

### 1. Give the load balancer a fixed IP

Agents dial the control plane on `:9000` and clients dial the data plane on `:8080`, so the
load balancer's address must not change. The simplest way is a **DHCP reservation** on the
router:

1. Open the router's admin page (usually `http://192.168.1.1`) and go to the DHCP / LAN
   settings. Some routers call it "static IP" or "address reservation".
2. Find the load balancer machine in the list of connected devices and note its MAC address.
3. Add a reservation that ties that MAC to an IP, for example `192.168.1.50`.
4. Renew the lease on the machine so it picks up the address:
   - macOS: `sudo ipconfig set en0 DHCP`
   - Linux (NetworkManager): `nmcli connection down <name> && nmcli connection up <name>`
5. Check it: `ipconfig getifaddr en0` on macOS, `ip -4 addr` on Linux.

A reservation beats setting a static address on the machine itself: the router knows about
it and will never lend that IP to another device. If you set it by hand anyway, pick an
address outside the router's DHCP range.

> **Watch out for private MAC addresses.** macOS, iOS, Android and Windows can use a random
> Wi-Fi MAC per network, and some rotate it over time. If the MAC changes, the reservation
> stops matching and the machine gets a different IP. You can spot one because the second
> hex digit is `2`, `6`, `A` or `E` (e.g. `32:15:…`). On macOS: System Settings → Wi-Fi →
> Details on your network → Private Wi-Fi address → **Fixed** or **Off**. An Ethernet cable
> avoids the problem entirely.

Nodes don't need a reservation: they find the load balancer, not the other way round.

### 2. Bind to an address other machines can reach

The addresses the control plane and data plane listen on (in
[`orchestrator/internal/config/config.go`](orchestrator/internal/config/config.go)) must be reachable from the rest of the
LAN: either the reserved IP (`<LB_ADDRESS>:9000`) or all interfaces (`:9000`, `:8080`).
Never `localhost` or `127.0.0.1`, which only accept connections from the same machine.
Binding to all interfaces saves you from keeping the code and the router in sync.

### 3. Open the ports

Only the load balancer needs inbound ports, `8080/tcp` and `9000/tcp`.

- macOS: the first run asks whether to allow incoming connections — allow it. If you missed
  the prompt: System Settings → Network → Firewall → Options.
- Linux with ufw: `sudo ufw allow 8080/tcp && sudo ufw allow 9000/tcp`

### 4. Check it from another machine

Put the reserved IP in `.env.local` (git-ignored) and start the load balancer:

```sh
cp .env.example .env.local   # then set LB_ADDRESS
set -a; source .env.local; set +a
cd orchestrator && go run ./cmd/orchestrator
```

Then, from any other machine on the LAN:

```sh
nc -vz <LB_ADDRESS> 9000   # control plane
nc -vz <LB_ADDRESS> 8080   # data plane
```

Both should report the connection as succeeded. If they time out, go back to the firewall;
if they are refused, the process is not listening on that address.

---

## Why

Because reading about kube-proxy, veth pairs, conntrack and control loops is not the same
as having had to make them work. Everything here exists to be built by hand at least once.

## License

MIT