// Package inteltask auto-generates artifacts (YARA rules, saved hunts) from intel data.
package inteltask

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/youredr/edr-backend/internal/models"
)

// Store is the subset of store.Store used by the generator.
type Store interface {
	GetIOC(ctx context.Context, id string) (*models.IOC, error)
	GetThreatActor(ctx context.Context, id, tenantID string) (*models.ThreatActor, error)
	GetActorIOCs(ctx context.Context, actorID, tenantID string, limit int) ([]models.IOC, error)
	UpsertYARARule(ctx context.Context, r *models.YARARule) error
	CreateSavedHunt(ctx context.Context, h *models.SavedHunt) error
	CreateIntelTask(ctx context.Context, t *models.IntelTask) error
	FinishIntelTask(ctx context.Context, id, artifactID, status string) error
}

// Generator creates intel artifacts in the background.
type Generator struct {
	store    Store
	log      zerolog.Logger
	tenantID string
}

// New creates a Generator.
func New(st Store, tenantID string, log zerolog.Logger) *Generator {
	return &Generator{
		store:    st,
		log:      log.With().Str("component", "inteltask").Logger(),
		tenantID: tenantID,
	}
}

// EnqueueForIOC checks a newly added IOC and generates a YARA rule if applicable.
// Called asynchronously from IOC creation handlers.
func (g *Generator) EnqueueForIOC(ctx context.Context, iocID string) {
	ioc, err := g.store.GetIOC(ctx, iocID)
	if err != nil {
		return
	}
	if ioc.Type != "hash_sha256" && ioc.Type != "hash_md5" {
		return
	}

	// Check VT detections from enrichment data.
	detections := vtDetections(ioc.Enrichment)
	if detections < 10 {
		return
	}

	task := &models.IntelTask{
		TenantID:   g.tenantID,
		Name:       fmt.Sprintf("YARA: auto_%s", ioc.Value[:16]),
		TaskType:   "yara_rule",
		SourceType: "ioc",
		SourceID:   iocID,
		CreatedBy:  "system",
	}
	if err := g.store.CreateIntelTask(ctx, task); err != nil {
		g.log.Warn().Err(err).Msg("create ioc yara task")
		return
	}

	yaraID, err := g.generateYARAFromIOC(ctx, ioc)
	if err != nil {
		g.log.Warn().Err(err).Str("ioc", iocID).Msg("generate YARA rule")
		_ = g.store.FinishIntelTask(ctx, task.ID, "", "failed")
		return
	}
	_ = g.store.FinishIntelTask(ctx, task.ID, yaraID, "done")
	g.log.Info().Str("ioc", iocID).Str("yara", yaraID).Msg("auto-generated YARA rule from IOC")
}

// EnqueueForActor generates a saved hunt query for all IOCs linked to the actor.
// Called asynchronously after actor creation/update.
func (g *Generator) EnqueueForActor(ctx context.Context, actorID string) {
	actor, err := g.store.GetThreatActor(ctx, actorID, g.tenantID)
	if err != nil {
		return
	}

	iocs, err := g.store.GetActorIOCs(ctx, actorID, g.tenantID, 500)
	if err != nil || len(iocs) == 0 {
		return
	}

	task := &models.IntelTask{
		TenantID:   g.tenantID,
		Name:       fmt.Sprintf("Hunt: %s indicators", actor.Name),
		TaskType:   "hunt",
		SourceType: "actor",
		SourceID:   actorID,
		CreatedBy:  "system",
	}
	if err := g.store.CreateIntelTask(ctx, task); err != nil {
		g.log.Warn().Err(err).Msg("create actor hunt task")
		return
	}

	huntID, err := g.generateHuntFromActor(ctx, actor, iocs)
	if err != nil {
		g.log.Warn().Err(err).Str("actor", actorID).Msg("generate actor hunt")
		_ = g.store.FinishIntelTask(ctx, task.ID, "", "failed")
		return
	}
	_ = g.store.FinishIntelTask(ctx, task.ID, huntID, "done")
	g.log.Info().Str("actor", actorID).Str("hunt", huntID).Msg("auto-generated hunt from actor")
}

// BuildIOCIntelContext returns a json.RawMessage suitable for merging into
// alert.Enrichments["intel_context"] when an IOC match fires.
// It is called on the hot path so it must not touch the DB.
func BuildIOCIntelContext(ioc *models.IOC) json.RawMessage {
	ctx := map[string]interface{}{
		"ioc_id":    ioc.ID,
		"ioc_type":  ioc.Type,
		"ioc_value": ioc.Value,
		"ioc_source": ioc.Source,
		"enriched_at": time.Now().UTC(),
	}
	if ioc.ActorID != nil {
		ctx["actor_id"] = *ioc.ActorID
	}
	if ioc.CampaignID != nil {
		ctx["campaign_id"] = *ioc.CampaignID
	}
	// Include VT summary if available.
	if det := vtDetections(ioc.Enrichment); det > 0 {
		ctx["vt_detections"] = det
	}
	b, _ := json.Marshal(ctx)
	return b
}

// ── private helpers ───────────────────────────────────────────────────────────

func (g *Generator) generateYARAFromIOC(ctx context.Context, ioc *models.IOC) (string, error) {
	hashField := "SHA256"
	if ioc.Type == "hash_md5" {
		hashField = "MD5"
	}
	safeName := sanitizeRuleName(ioc.Value)
	family := vtFamily(ioc.Enrichment)
	meta := fmt.Sprintf(`
        description = "Auto-generated from IOC %s"
        hash = "%s"
        source = "%s"
        date = "%s"`, ioc.ID, ioc.Value, ioc.Source, time.Now().Format("2006-01-02"))
	if family != "" {
		meta += fmt.Sprintf("\n        family = \"%s\"", family)
	}

	ruleText := fmt.Sprintf(`rule auto_%s {
    meta:%s
    condition:
        hash.%s(0, filesize) == "%s"
}`, safeName, meta, strings.ToLower(hashField), strings.ToLower(ioc.Value))

	r := &models.YARARule{
		ID:          "yara-auto-" + ioc.ID,
		Name:        "auto_" + safeName,
		Description: fmt.Sprintf("Auto-generated from %s IOC %s (VT: %d detections)", ioc.Type, ioc.Value, vtDetections(ioc.Enrichment)),
		RuleText:    ruleText,
		Enabled:     true,
		Severity:    ioc.Severity,
		Tags:        pq.StringArray{"auto", "ioc", ioc.Type},
		Author:      "inteltask/system",
	}
	if err := g.store.UpsertYARARule(ctx, r); err != nil {
		return "", err
	}
	return r.ID, nil
}

func (g *Generator) generateHuntFromActor(ctx context.Context, actor *models.ThreatActor, iocs []models.IOC) (string, error) {
	var ips, domains, hashes []string
	for _, ioc := range iocs {
		switch ioc.Type {
		case "ip":
			ips = append(ips, ioc.Value)
		case "domain":
			domains = append(domains, ioc.Value)
		case "hash_sha256", "hash_md5":
			hashes = append(hashes, ioc.Value)
		}
	}

	var clauses []string
	if len(ips) > 0 {
		quoted := quoteList(ips)
		clauses = append(clauses, fmt.Sprintf("(payload->>'dst_ip' IN (%s) OR payload->>'src_ip' IN (%s))", quoted, quoted))
	}
	if len(domains) > 0 {
		clauses = append(clauses, fmt.Sprintf("payload->>'dns_query' IN (%s)", quoteList(domains)))
	}
	if len(hashes) > 0 {
		quoted := quoteList(hashes)
		clauses = append(clauses, fmt.Sprintf("(payload->>'exe_hash' IN (%s) OR payload->>'hash_after' IN (%s))", quoted, quoted))
	}

	if len(clauses) == 0 {
		return "", fmt.Errorf("no usable IOCs for actor %s", actor.ID)
	}

	query := fmt.Sprintf("SELECT * FROM events WHERE %s LIMIT 500", strings.Join(clauses, " OR "))

	h := &models.SavedHunt{
		TenantID: g.tenantID,
		Name:     fmt.Sprintf("%s — auto hunt (%s)", actor.Name, time.Now().Format("2006-01-02")),
		Query:    query,
		SourceID: actor.ID,
	}
	if err := g.store.CreateSavedHunt(ctx, h); err != nil {
		return "", err
	}
	return h.ID, nil
}

func vtDetections(enrichment json.RawMessage) int {
	if len(enrichment) == 0 {
		return 0
	}
	var e struct {
		VTDetections int `json:"vt_detections"`
	}
	if err := json.Unmarshal(enrichment, &e); err != nil {
		return 0
	}
	return e.VTDetections
}

func vtFamily(enrichment json.RawMessage) string {
	if len(enrichment) == 0 {
		return ""
	}
	var e struct {
		VTMalwareFamily string `json:"vt_malware_family"`
	}
	_ = json.Unmarshal(enrichment, &e)
	return e.VTMalwareFamily
}

func sanitizeRuleName(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	r := b.String()
	if len(r) > 32 {
		r = r[:32]
	}
	return r
}

func quoteList(vals []string) string {
	quoted := make([]string, 0, len(vals))
	for _, v := range vals {
		// Single-quote escape: replace ' with ''
		quoted = append(quoted, "'"+strings.ReplaceAll(v, "'", "''")+"'")
	}
	return strings.Join(quoted, ", ")
}
