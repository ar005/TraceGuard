// internal/api/forensics_acquire.go
//
// Forensic Acquisition — analyst-triggered remote artifact collection.
//
// Flow:
//   1. Analyst POSTs /agents/:id/forensics/collect → backend creates a pending job.
//   2. Agent polls GET /agents/:id/forensics/pending (API-key auth) every 60s.
//   3. Agent POSTs collected bundle to /forensics/jobs/:id/bundle.
//   4. Analyst downloads via GET /forensics/jobs/:id/download.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

// forensicsUploadStore is the narrow store interface needed by the bundle upload handler.
type forensicsUploadStore interface {
	GetForensicsJobByID(ctx context.Context, id string) (*models.ForensicsJob, error)
	UpdateForensicsJobFailed(ctx context.Context, id, errMsg string) error
	UpdateForensicsJobDone(ctx context.Context, id, bundlePath string, bundleSize int64) error
}

func forensicsBundleDir() string {
	if d := os.Getenv("EDR_FORENSICS_DIR"); d != "" {
		return d
	}
	return "/var/lib/edr/forensics"
}

func getTenantID(c *gin.Context) string {
	tid, _ := c.Get("tenant_id")
	s, _ := tid.(string)
	return s
}

// handleListForensicsJobs returns all forensics jobs for the caller tenant.
func (s *Server) handleListForensicsJobs(c *gin.Context) {
	tid := getTenantID(c)
	jobs, err := s.store.ListForensicsJobs(c.Request.Context(), tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"jobs": jobs})
}

// handleGetForensicsJob returns a single job.
func (s *Server) handleGetForensicsJob(c *gin.Context) {
	id := c.Param("id")
	tid := getTenantID(c)
	job, err := s.store.GetForensicsJob(c.Request.Context(), id, tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}
	c.JSON(http.StatusOK, job)
}

// handleCreateForensicsJob creates a new pending forensics job for a specific agent.
func (s *Server) handleCreateForensicsJob(c *gin.Context) {
	agentID := c.Param("id")
	tid := getTenantID(c)

	var req struct {
		JobType string          `json:"job_type"` // artifacts | process_memory | file | full
		Params  json.RawMessage `json:"params"`   // {"pid":1234} or {"path":"/etc/passwd"}
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	validTypes := map[string]bool{"artifacts": true, "process_memory": true, "file": true, "full": true}
	if !validTypes[req.JobType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "job_type must be one of: artifacts, process_memory, file, full"})
		return
	}
	if req.Params == nil {
		req.Params = json.RawMessage(`{}`)
	}

	// Resolve hostname from agent record (best-effort).
	hostname := ""
	if ag, err := s.store.GetAgent(c.Request.Context(), agentID, tid); err == nil {
		hostname = ag.Hostname
	}

	job := &models.ForensicsJob{
		ID:        uuid.New().String(),
		TenantID:  tid,
		AgentID:   agentID,
		Hostname:  hostname,
		JobType:   req.JobType,
		Params:    req.Params,
		CreatedBy: c.GetString("email"),
	}
	if err := s.store.CreateForensicsJob(c.Request.Context(), job); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, job)
}

// handleForensicsPending is called by the agent to poll for pending jobs.
// Auth: agent API key (X-Agent-Key header or Bearer token).
func (s *Server) handleForensicsPending(c *gin.Context) {
	agentID := c.Param("id")
	jobs, err := s.store.GetPendingForensicsJobs(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"jobs": jobs})
}

// handleForensicsUploadBundle accepts the tar.gz bundle from the agent.
// Auth: agent API key + X-Agent-ID header must match the job's assigned agent.
func (s *Server) handleForensicsUploadBundle(c *gin.Context) {
	forensicsUploadBundleFrom(c, s.store, s.log)
}

func forensicsUploadBundleFrom(c *gin.Context, st forensicsUploadStore, log zerolog.Logger) {
	jobID := c.Param("id")

	job, err := st.GetForensicsJobByID(c.Request.Context(), jobID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}
	// Verify the uploading agent owns this job.
	callerAgentID := c.GetHeader("X-Agent-ID")
	if callerAgentID == "" || callerAgentID != job.AgentID {
		c.JSON(http.StatusForbidden, gin.H{"error": "agent not authorized for this job"})
		return
	}
	if job.Status != "collecting" {
		c.JSON(http.StatusConflict, gin.H{"error": "job not in collecting state"})
		return
	}

	// Agent signals a collection failure via this header instead of uploading a bundle.
	if errMsg := c.GetHeader("X-Forensics-Error"); errMsg != "" {
		if err := st.UpdateForensicsJobFailed(c.Request.Context(), jobID, errMsg); err != nil {
			log.Error().Err(err).Str("job_id", jobID).Msg("failed to mark forensics job failed")
		}
		c.JSON(http.StatusOK, gin.H{"status": "recorded_failure"})
		return
	}

	forensicsDir := forensicsBundleDir()
	if err := os.MkdirAll(forensicsDir, 0700); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot create forensics dir"})
		return
	}

	fileName := fmt.Sprintf("%s.tar.gz", jobID)
	bundlePath := filepath.Join(forensicsDir, fileName)

	// Limit bundle size to 500 MB.
	const maxBundleSize = 500 * 1024 * 1024
	f, err := os.Create(bundlePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot create bundle file"})
		return
	}
	defer f.Close()

	written, err := io.Copy(f, io.LimitReader(c.Request.Body, maxBundleSize))
	if err != nil {
		os.Remove(bundlePath)
		_ = st.UpdateForensicsJobFailed(c.Request.Context(), jobID, "upload error: "+err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload failed"})
		return
	}

	if err := st.UpdateForensicsJobDone(c.Request.Context(), jobID, bundlePath, written); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"received": written})
}

// handleForensicsDownload streams the bundle file to the analyst.
func (s *Server) handleForensicsDownload(c *gin.Context) {
	jobID := c.Param("id")
	tid := getTenantID(c)

	job, err := s.store.GetForensicsJob(c.Request.Context(), jobID, tid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}
	if job.Status != "ready" {
		c.JSON(http.StatusConflict, gin.H{"error": "bundle not ready", "status": job.Status})
		return
	}

	// Prevent path traversal — bundle_path is set by our own code but be safe.
	forensicsDir := forensicsBundleDir()
	clean := filepath.Clean(job.BundlePath)
	if !strings.HasPrefix(clean, filepath.Clean(forensicsDir)) {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid bundle path"})
		return
	}

	fileName := fmt.Sprintf("forensics-%s-%s.tar.gz", sanitizeFilename(job.Hostname), jobID[:8])
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
	c.Header("Content-Type", "application/gzip")
	c.File(job.BundlePath)
}
