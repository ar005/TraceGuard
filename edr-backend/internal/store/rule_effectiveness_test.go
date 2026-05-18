package store

import (
	"testing"

	"github.com/youredr/edr-backend/internal/models"
)

func TestRuleEffectivenessLabel(t *testing.T) {
	cases := []struct {
		name string
		row  models.RuleEffectivenessRow
		want string
	}{
		{
			name: "never fired → silent",
			row:  models.RuleEffectivenessRow{TotalFires: 0, Fires7d: 0},
			want: "silent",
		},
		{
			name: "has fires but none this week → stale",
			row:  models.RuleEffectivenessRow{TotalFires: 50, Fires7d: 0, CloseRate: 80},
			want: "stale",
		},
		{
			name: "high close rate, low FP → effective",
			row:  models.RuleEffectivenessRow{TotalFires: 20, Fires7d: 5, CloseRate: 75, FPRate: 10},
			want: "effective",
		},
		{
			name: "exact effective threshold",
			row:  models.RuleEffectivenessRow{TotalFires: 10, Fires7d: 1, CloseRate: 60, FPRate: 20},
			want: "effective",
		},
		{
			name: "low close rate → noisy",
			row:  models.RuleEffectivenessRow{TotalFires: 100, Fires7d: 30, CloseRate: 15, FPRate: 5},
			want: "noisy",
		},
		{
			name: "high FP rate → noisy",
			row:  models.RuleEffectivenessRow{TotalFires: 50, Fires7d: 10, CloseRate: 50, FPRate: 45},
			want: "noisy",
		},
		{
			name: "middle range → active",
			row:  models.RuleEffectivenessRow{TotalFires: 30, Fires7d: 8, CloseRate: 45, FPRate: 15},
			want: "active",
		},
		{
			name: "fires this week, high FP on boundary → noisy",
			row:  models.RuleEffectivenessRow{TotalFires: 10, Fires7d: 2, CloseRate: 29, FPRate: 0},
			want: "noisy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleEffectivenessLabel(tc.row)
			if got != tc.want {
				t.Errorf("label = %q, want %q (row=%+v)", got, tc.want, tc.row)
			}
		})
	}
}
