// internal/correlation/stitcher.go
//
// Stitcher enriches XdrEvents from non-endpoint sources with endpoint/identity
// context derived from two caches:
//
//   - IPMapper: net.IP → agentID + userUID (populated by endpoint events)
//   - identity_graph table (read via Store): userUID → canonical identity
//
// The Stitcher is called in the NATS detection/store workers after an XdrEvent
// arrives from a network, cloud, or identity connector.  It mutates the event
// in-place (fills SourceID, UserUID, Enrichments) before the event is stored.
//
// Enrichment is best-effort: if no match is found the event passes through
// unchanged.

package correlation

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-backend/internal/models"
)

// IdentityStore is the minimal interface the Stitcher needs from the DB layer.
type IdentityStore interface {
	// GetIdentityByUID returns the identity_graph row for the given userUID,
	// or nil if not found.
	GetIdentityByUID(ctx context.Context, userUID string) (*models.IdentityRecord, error)
}

// Stitcher enriches XdrEvents with IP→endpoint and user identity context.
type Stitcher struct {
	ipmap    *IPMapper
	idStore  IdentityStore
	log      zerolog.Logger
	cacheTTL time.Duration
}

// NewStitcher creates a Stitcher backed by the given IPMapper and IdentityStore.
func NewStitcher(ipmap *IPMapper, idStore IdentityStore, log zerolog.Logger) *Stitcher {
	return &Stitcher{
		ipmap:    ipmap,
		idStore:  idStore,
		log:      log.With().Str("component", "stitcher").Logger(),
		cacheTTL: 30 * time.Minute,
	}
}

// Enrich fills in endpoint/identity context on ev from the IP and identity caches.
// It is safe to call concurrently.
func (s *Stitcher) Enrich(ctx context.Context, ev *models.XdrEvent) {
	enrichments := map[string]interface{}{}

	// --- IP attribution ---
	if ev.SrcIP != nil {
		if entry := s.ipmap.Get(*ev.SrcIP); entry != nil {
			if ev.SourceID == "" || ev.SourceID == "default" {
				ev.SourceID = entry.AgentID
			}
			if ev.UserUID == "" {
				ev.UserUID = entry.UserUID
			}
			enrichments["src_agent_id"] = entry.AgentID
			if entry.UserUID != "" {
				enrichments["src_user_uid"] = entry.UserUID
			}
		}
	}
	if ev.DstIP != nil {
		if entry := s.ipmap.Get(*ev.DstIP); entry != nil {
			enrichments["dst_agent_id"] = entry.AgentID
			if entry.UserUID != "" {
				enrichments["dst_user_uid"] = entry.UserUID
			}
		}
	}

	// --- Identity enrichment ---
	if ev.UserUID != "" {
		if rec, err := s.idStore.GetIdentityByUID(ctx, ev.UserUID); err == nil && rec != nil {
			enrichments["identity_display_name"] = rec.DisplayName
			enrichments["identity_uid"] = rec.CanonicalUID
			enrichments["identity_department"] = rec.Department
			enrichments["identity_privileged"] = rec.IsPrivileged
			enrichments["identity_risk_score"] = rec.RiskScore
		}
	}

	if len(enrichments) == 0 {
		return
	}

	// Merge with any existing enrichments.
	existing := map[string]interface{}{}
	if len(ev.Enrichments) > 0 {
		_ = json.Unmarshal(ev.Enrichments, &existing)
	}
	for k, v := range enrichments {
		existing[k] = v
	}
	ev.Enrichments, _ = json.Marshal(existing)
}

// LearnIP records a net.IP → agentID+userUID mapping for future stitching.
// Call this from the ingest pipeline for every endpoint event that carries IPs.
func (s *Stitcher) LearnIP(ip net.IP, agentID, userUID string) {
	s.ipmap.Set(ip, agentID, userUID)
}
