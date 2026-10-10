package agent

import (
	"crypto/sha256"
	"encoding/base32"
)

// chainHashLength keeps every chain name at prefix (8) + "-" + 16 = 25 chars,
// under the 28 chars iptables allows, whatever the service or node is called
const chainHashLength = 16

// chainName builds an iptables chain name the way kube-proxy does: a fixed prefix plus a
// hash of what the chain stands for. Readable names like KUBE-SEP-<service>-<node> overflow
// the iptables limit as soon as the service or the hostname gets a bit long, so the
// readable part goes into a -m comment on the rules instead
func chainName(prefix, identity string) string {
	hash := sha256.Sum256([]byte(identity))
	return prefix + "-" + base32.StdEncoding.EncodeToString(hash[:])[:chainHashLength]
}

// endpointChain is the KUBE-SEP chain of one backend (local pod or remote node)
func endpointChain(backendID string) string {
	return chainName(KubeEndpointChainPrefix, backendID)
}
