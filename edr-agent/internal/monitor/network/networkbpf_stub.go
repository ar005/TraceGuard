// internal/monitor/network/networkbpf_stub.go
//
// Stub types for bpf2go-generated code.

package network

import "github.com/cilium/ebpf"

// NetworkObjects contains all eBPF programs and maps after loading.
type NetworkObjects struct {
	FentryTcpConnect    *ebpf.Program
	FexitInetCskAccept  *ebpf.Program
	TpInetSockSetState  *ebpf.Program
	FentryTcpClose      *ebpf.Program
	KprobeUdpSendmsg    *ebpf.Program
	KprobeUdpRecvmsg    *ebpf.Program
	NetworkEvents       *ebpf.Map
}

func (o *NetworkObjects) Close() {
	for _, p := range []*ebpf.Program{
		o.FentryTcpConnect, o.FexitInetCskAccept, o.TpInetSockSetState,
		o.FentryTcpClose, o.KprobeUdpSendmsg, o.KprobeUdpRecvmsg,
	} {
		if p != nil { p.Close() }
	}
	if o.NetworkEvents != nil { o.NetworkEvents.Close() }
}

// LoadNetworkObjects loads eBPF programs from the compiled object file.
func LoadNetworkObjects(obj *NetworkObjects, opts *ebpf.CollectionOptions) error {
	return &ebpf.VerifierError{Log: []string{"eBPF objects not compiled — run make generate"}}
}
