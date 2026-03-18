// internal/db/migration_dns_rules.go
// DNS-specific detection rules — appended to the migrations slice at init time.

package db

func init() {
	migrations = append(migrations, struct {
		name string
		sql  string
	}{
		name: "seed_dns_detection_rules",
		sql: `
		INSERT INTO rules (id, name, description, severity, event_types, conditions, mitre_ids, author)
		VALUES
		(
			'rule-dns-dga-domain',
			'DGA Domain Detected',
			'A DNS query resolved a domain with characteristics of Domain Generation Algorithms — excessive length (>50 chars) or high proportion of digits and hyphens. Common in malware C2 infrastructure.',
			3,
			ARRAY['NET_DNS'],
			'[{"field":"dns_query","op":"regex","value":"^[a-z0-9-]{50,}\\\\.|[0-9]{8,}|([a-z]{2,4}[0-9]){4,}"}]',
			ARRAY['T1568.002'],
			'system'
		),
		(
			'rule-dns-rare-tld',
			'DNS Query to Rare/Suspicious TLD',
			'A DNS query targeted a top-level domain frequently abused by threat actors for phishing, malware distribution, and C2 infrastructure.',
			2,
			ARRAY['NET_DNS'],
			'[{"field":"dns_query","op":"regex","value":"\\\\.(tk|xyz|top|pw|cc|ws|click|link|work|date|download|racing|stream|gdn|bid)$"}]',
			ARRAY['T1071.004'],
			'system'
		)
		ON CONFLICT (id) DO NOTHING;
		`,
	})
}
