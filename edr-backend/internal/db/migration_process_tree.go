package db

func init() {
	migrations = append(migrations, struct {
		name string
		sql  string
	}{
		name: "add_process_tree_indexes",
		sql: `
		CREATE INDEX IF NOT EXISTS events_process_pid_idx
			ON events ((payload->'process'->>'pid'))
			WHERE event_type = 'PROCESS_EXEC';
		CREATE INDEX IF NOT EXISTS events_process_ppid_idx
			ON events ((payload->'process'->>'ppid'))
			WHERE event_type = 'PROCESS_EXEC';
		`,
	})
}
