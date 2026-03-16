// internal/monitor/file/filebpf_stub.go
//
// Stub types for bpf2go-generated code.

package file

import "github.com/cilium/ebpf"

// FileObjects contains all eBPF programs and maps after loading.
type FileObjects struct {
	KprobeVfsWrite              *ebpf.Program
	KprobeVfsCreate             *ebpf.Program
	KprobeVfsUnlink             *ebpf.Program
	KprobeVfsRename             *ebpf.Program
	KprobeSecurityInodeSetattr  *ebpf.Program
	FileEvents                  *ebpf.Map
}

func (o *FileObjects) Close() {
	for _, p := range []*ebpf.Program{
		o.KprobeVfsWrite, o.KprobeVfsCreate, o.KprobeVfsUnlink,
		o.KprobeVfsRename, o.KprobeSecurityInodeSetattr,
	} {
		if p != nil { p.Close() }
	}
	if o.FileEvents != nil { o.FileEvents.Close() }
}

// LoadFileObjects loads eBPF programs from the compiled object file.
func LoadFileObjects(obj *FileObjects, opts *ebpf.CollectionOptions) error {
	return &ebpf.VerifierError{Log: []string{"eBPF objects not compiled — run make generate"}}
}
