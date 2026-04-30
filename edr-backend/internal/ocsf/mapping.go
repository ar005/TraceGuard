// internal/ocsf/mapping.go
//
// Maps TraceGuard native event types to OCSF (Open Cybersecurity Schema Framework)
// class_uid and category_uid values.
//
// OCSF categories:
//   1  System Activity
//   2  Findings
//   3  Identity & Access Management
//   4  Network Activity
//   5  Discovery
//   6  Application Activity
//
// See: https://schema.ocsf.io/classes and xdr.md §2.2 for the full table.

package ocsf

const (
	// Category UIDs
	CategorySystemActivity  = 1
	CategoryFindings        = 2
	CategoryIdentityAccess  = 3
	CategoryNetworkActivity = 4
	CategoryDiscovery       = 5
	CategoryAppActivity     = 6

	// Class UIDs (subset used by TraceGuard)
	ClassFileSystemActivity  = 1001
	ClassNetworkActivity     = 4001
	ClassHTTPActivity        = 4002
	ClassDNSActivity         = 4003
	ClassTLSActivity         = 4006
	ClassProcessActivity     = 1007
	ClassKernelActivity      = 1009
	ClassMemoryActivity      = 1010
	ClassUSBActivity         = 1005
	ClassAuthentication      = 3002
	ClassAuthorizeSession    = 3005
	ClassDetectionFinding    = 2004
	ClassAPIActivity         = 6003
	ClassCloudAPIActivity    = 4001 // reuse NetworkActivity UID for cloud API events
	ClassPolicyChange        = 6001
	ClassUnknown             = 0

	// Category UIDs for XDR sources
	CategoryIdentityActivity = 3 // IAM category
	CategoryCloudActivity    = 4 // NetworkActivity category (cloud management plane)
)

// classMap maps TraceGuard event type strings to OCSF class_uid.
var classMap = map[string]int{
	"PROCESS_EXEC":        ClassProcessActivity,
	"PROCESS_FORK":        ClassProcessActivity,
	"PROCESS_EXIT":        ClassProcessActivity,
	"FILE_CREATE":         ClassFileSystemActivity,
	"FILE_WRITE":          ClassFileSystemActivity,
	"FILE_DELETE":         ClassFileSystemActivity,
	"FILE_RENAME":         ClassFileSystemActivity,
	"FILE_CHMOD":          ClassFileSystemActivity,
	"NET_CONNECT":         ClassNetworkActivity,
	"NET_ACCEPT":          ClassNetworkActivity,
	"NET_CLOSE":           ClassNetworkActivity,
	"NET_DNS":             ClassDNSActivity,
	"NET_TLS_SNI":         ClassTLSActivity,
	"LOGIN_SUCCESS":       ClassAuthentication,
	"LOGIN_FAILED":        ClassAuthentication,
	"SUDO_EXEC":           ClassAuthorizeSession,
	"MEMORY_INJECT":       ClassMemoryActivity,
	"KMOD_LOAD":           ClassKernelActivity,
	"KMOD_UNLOAD":         ClassKernelActivity,
	"USB_CONNECT":         ClassUSBActivity,
	"USB_DISCONNECT":      ClassUSBActivity,
	"BROWSER_REQUEST":     ClassHTTPActivity,
	"CRON_MODIFY":         ClassFileSystemActivity,
	"PIPE_CREATE":         ClassFileSystemActivity,
	"SHARE_MOUNT":         ClassNetworkActivity,
	"SHARE_UNMOUNT":       ClassNetworkActivity,
}

// categoryMap maps TraceGuard event types to OCSF category_uid.
var categoryMap = map[string]int16{
	"PROCESS_EXEC":  CategorySystemActivity,
	"PROCESS_FORK":  CategorySystemActivity,
	"PROCESS_EXIT":  CategorySystemActivity,
	"FILE_CREATE":   CategorySystemActivity,
	"FILE_WRITE":    CategorySystemActivity,
	"FILE_DELETE":   CategorySystemActivity,
	"FILE_RENAME":   CategorySystemActivity,
	"FILE_CHMOD":    CategorySystemActivity,
	"NET_CONNECT":   CategoryNetworkActivity,
	"NET_ACCEPT":    CategoryNetworkActivity,
	"NET_CLOSE":     CategoryNetworkActivity,
	"NET_DNS":       CategoryNetworkActivity,
	"NET_TLS_SNI":   CategoryNetworkActivity,
	"LOGIN_SUCCESS": CategoryIdentityAccess,
	"LOGIN_FAILED":  CategoryIdentityAccess,
	"SUDO_EXEC":     CategoryIdentityAccess,
	"MEMORY_INJECT": CategorySystemActivity,
	"KMOD_LOAD":     CategorySystemActivity,
	"KMOD_UNLOAD":   CategorySystemActivity,
	"USB_CONNECT":   CategorySystemActivity,
	"USB_DISCONNECT": CategorySystemActivity,
	"BROWSER_REQUEST": CategoryNetworkActivity,
	"CRON_MODIFY":   CategorySystemActivity,
	"PIPE_CREATE":   CategorySystemActivity,
	"SHARE_MOUNT":   CategoryNetworkActivity,
	"SHARE_UNMOUNT": CategoryNetworkActivity,
}

// ClassUID returns the OCSF class_uid for a TraceGuard event type.
// Returns ClassUnknown (0) for unmapped types.
func ClassUID(eventType string) int {
	if uid, ok := classMap[eventType]; ok {
		return uid
	}
	return ClassUnknown
}

// CategoryUID returns the OCSF category_uid for a TraceGuard event type.
// Returns 0 for unmapped types.
func CategoryUID(eventType string) int16 {
	if uid, ok := categoryMap[eventType]; ok {
		return uid
	}
	return 0
}
