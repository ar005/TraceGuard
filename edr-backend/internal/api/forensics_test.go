// forensics_test.go — unit tests for the forensics bundle upload handler.

package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

func init() { gin.SetMode(gin.TestMode) }

// ── mock store ────────────────────────────────────────────────────────────────

type mockForensicsStore struct {
	job            *models.ForensicsJob
	getErr         error
	failedJobID    string
	failedErrMsg   string
	failErr        error
	doneJobID      string
	doneBundlePath string
	doneBundleSize int64
	doneErr        error
}

func (m *mockForensicsStore) GetForensicsJobByID(_ context.Context, id string) (*models.ForensicsJob, error) {
	return m.job, m.getErr
}
func (m *mockForensicsStore) UpdateForensicsJobFailed(_ context.Context, id, errMsg string) error {
	m.failedJobID = id
	m.failedErrMsg = errMsg
	return m.failErr
}
func (m *mockForensicsStore) UpdateForensicsJobDone(_ context.Context, id, path string, size int64) error {
	m.doneJobID = id
	m.doneBundlePath = path
	m.doneBundleSize = size
	return m.doneErr
}

// ── helpers ───────────────────────────────────────────────────────────────────

func setupForensicsRouter(st forensicsUploadStore) *gin.Engine {
	r := gin.New()
	log := zerolog.Nop()
	r.POST("/forensics/jobs/:id/bundle", func(c *gin.Context) {
		forensicsUploadBundleFrom(c, st, log)
	})
	return r
}

func collectingJob(agentID string) *models.ForensicsJob {
	return &models.ForensicsJob{
		ID:      "job-1",
		AgentID: agentID,
		Status:  "collecting",
		JobType: "process_memory",
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestForensicsUpload_ErrorHeader verifies that when the agent sends
// X-Forensics-Error, the job is marked failed and HTTP 200 is returned.
func TestForensicsUpload_ErrorHeader(t *testing.T) {
	st := &mockForensicsStore{job: collectingJob("agent-1")}
	r := setupForensicsRouter(st)

	req, _ := http.NewRequest("POST", "/forensics/jobs/job-1/bundle", bytes.NewReader(nil))
	req.Header.Set("X-Agent-ID", "agent-1")
	req.Header.Set("X-Forensics-Error", "disk full on agent")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if st.failedJobID != "job-1" {
		t.Errorf("UpdateForensicsJobFailed not called with job-1, got %q", st.failedJobID)
	}
	if st.failedErrMsg != "disk full on agent" {
		t.Errorf("wrong error msg: %q", st.failedErrMsg)
	}
	// No file upload should have been attempted.
	if st.doneJobID != "" {
		t.Error("UpdateForensicsJobDone should not have been called")
	}
}

// TestForensicsUpload_JobNotFound returns 404 when job doesn't exist.
func TestForensicsUpload_JobNotFound(t *testing.T) {
	st := &mockForensicsStore{getErr: errors.New("not found")}
	r := setupForensicsRouter(st)

	req, _ := http.NewRequest("POST", "/forensics/jobs/nope/bundle", bytes.NewReader(nil))
	req.Header.Set("X-Agent-ID", "agent-1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestForensicsUpload_WrongAgent returns 403 when agent ID doesn't match job.
func TestForensicsUpload_WrongAgent(t *testing.T) {
	st := &mockForensicsStore{job: collectingJob("agent-correct")}
	r := setupForensicsRouter(st)

	req, _ := http.NewRequest("POST", "/forensics/jobs/job-1/bundle", bytes.NewReader(nil))
	req.Header.Set("X-Agent-ID", "agent-wrong")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

// TestForensicsUpload_JobNotCollecting returns 409 for wrong status.
func TestForensicsUpload_JobNotCollecting(t *testing.T) {
	job := collectingJob("agent-1")
	job.Status = "ready"
	st := &mockForensicsStore{job: job}
	r := setupForensicsRouter(st)

	req, _ := http.NewRequest("POST", "/forensics/jobs/job-1/bundle", bytes.NewReader(nil))
	req.Header.Set("X-Agent-ID", "agent-1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
}

// TestForensicsUpload_ErrorHeader_StoreFailure still returns 200 even when
// the store call to UpdateForensicsJobFailed itself errors.
func TestForensicsUpload_ErrorHeader_StoreFailure(t *testing.T) {
	st := &mockForensicsStore{
		job:     collectingJob("agent-1"),
		failErr: errors.New("db unavailable"),
	}
	r := setupForensicsRouter(st)

	req, _ := http.NewRequest("POST", "/forensics/jobs/job-1/bundle", bytes.NewReader(nil))
	req.Header.Set("X-Agent-ID", "agent-1")
	req.Header.Set("X-Forensics-Error", "collection failed")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should still return 200 — the error is logged but not propagated.
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
