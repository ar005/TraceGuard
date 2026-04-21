// internal/container/detect.go
//
// Container and Kubernetes awareness for the EDR agent.
// Detects whether a process runs inside a container and extracts
// metadata (runtime, container ID, pod name, namespace).

package container

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Info holds container metadata for a process.
type Info struct {
	ContainerID string `json:"container_id,omitempty"`
	Runtime     string `json:"runtime,omitempty"`     // docker, containerd, podman, cri-o
	ImageName   string `json:"image_name,omitempty"`
	PodName     string `json:"pod_name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
}

// Known cgroup path patterns for container runtimes.
// Each pattern captures the 64-char hex container ID.
var cgroupPatterns = []struct {
	re      *regexp.Regexp
	runtime string
}{
	// Docker: /docker/<id> or /system.slice/docker-<id>.scope
	{regexp.MustCompile(`/docker[/-]([0-9a-f]{64})`), "docker"},
	// Containerd (Kubernetes CRI): /cri-containerd-<id>.scope or /containerd/<id>
	{regexp.MustCompile(`/cri-containerd-([0-9a-f]{64})`), "containerd"},
	{regexp.MustCompile(`/containerd/([0-9a-f]{64})`), "containerd"},
	// Podman: /libpod-<id>.scope
	{regexp.MustCompile(`/libpod-([0-9a-f]{64})`), "podman"},
	// CRI-O: /crio-<id>.scope or /cri-o-<id>.scope
	{regexp.MustCompile(`/cri-?o-([0-9a-f]{64})`), "cri-o"},
	// Generic fallback: any path component that is a 64-char hex string
	{regexp.MustCompile(`/([0-9a-f]{64})`), ""},
}

// kubepodsPattern matches Kubernetes cgroup paths like /kubepods/burstable/pod<uuid>/...
var kubepodsPattern = regexp.MustCompile(`/kubepods[./]`)

// Detect reads /proc/<pid>/cgroup to determine if a process is running
// in a container. Returns nil if the process is not containerized.
func Detect(pid uint32) *Info {
	cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return nil
	}

	cgroupStr := string(cgroupData)

	// Try to extract container ID and runtime from cgroup paths.
	var containerID, runtime string
	for _, p := range cgroupPatterns {
		m := p.re.FindStringSubmatch(cgroupStr)
		if len(m) >= 2 {
			containerID = m[1]
			runtime = p.runtime
			break
		}
	}

	if containerID == "" {
		return nil
	}

	info := &Info{
		ContainerID: containerID[:12], // short form like docker ps
		Runtime:     runtime,
	}

	// Kubernetes detection: check cgroup for kubepods prefix or
	// process environment for KUBERNETES_SERVICE_HOST.
	isK8s := kubepodsPattern.MatchString(cgroupStr)
	if !isK8s {
		isK8s = hasKubernetesEnv(pid)
	}

	if isK8s {
		if info.Runtime == "" {
			info.Runtime = "containerd" // default k8s runtime
		}
		info.Namespace, info.PodName = extractK8sMetadata(pid)
	}

	// Try to resolve the container image name from the runtime.
	info.ImageName = resolveImageName(pid, info.Runtime)

	return info
}

// hasKubernetesEnv checks /proc/<pid>/environ for KUBERNETES_SERVICE_HOST.
func hasKubernetesEnv(pid uint32) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "KUBERNETES_SERVICE_HOST=")
}

// extractK8sMetadata tries to extract the pod name and namespace from
// the process environment. In Kubernetes, HOSTNAME is typically set to
// the pod name. The namespace can sometimes be found in
// /var/run/secrets/kubernetes.io/serviceaccount/namespace inside the
// container, which we read via the process's root filesystem.
func extractK8sMetadata(pid uint32) (namespace, podName string) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return "", ""
	}

	envs := strings.Split(string(data), "\x00")
	for _, env := range envs {
		kv := strings.SplitN(env, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "HOSTNAME":
			podName = kv[1]
		case "POD_NAMESPACE":
			// Some pods inject this via the Downward API.
			namespace = kv[1]
		}
	}

	// If namespace wasn't found in env vars, try the service account token mount.
	if namespace == "" {
		nsPath := fmt.Sprintf("/proc/%d/root/var/run/secrets/kubernetes.io/serviceaccount/namespace", pid)
		if raw, err := os.ReadFile(nsPath); err == nil {
			namespace = strings.TrimSpace(string(raw))
		}
	}

	return namespace, podName
}

// resolveImageName attempts a best-effort lookup of the container image.
// For Docker, it reads /proc/<pid>/root/.dockerenv existence and checks
// the container hostname against the overlay mount info.
// This is inherently limited without talking to the runtime socket.
func resolveImageName(pid uint32, runtime string) string {
	// Best-effort: read the overlay upperdir from /proc/<pid>/mountinfo
	// and try to extract the image reference. This is runtime-specific
	// and fragile, so we keep it simple.
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		// Look for overlay mount on / with an image reference in the options.
		if !strings.Contains(line, "overlay") {
			continue
		}
		// Docker/containerd sometimes encode image digest in lowerdir paths.
		// This is too fragile for production; return empty for now.
		// A proper implementation would query the container runtime API.
		_ = line
		break
	}

	return ""
}
