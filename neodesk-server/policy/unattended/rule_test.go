package unattended

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/neodeskapp/neodesk/neodesk-server/db"
)

type vector struct {
	Name         string   `json:"name"`
	Mode         *string  `json:"mode"`
	OrgOperators []string `json:"org_operators"`
	Access       *Access  `json:"access"`
	Caller       string   `json:"caller"`
	Now          string   `json:"now"`
	Want         string   `json:"want"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/rule-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return doc.Vectors
}

// TestRuleVectors runs the vectors the receiver app shares: every one must
// give the answer it names.
func TestRuleVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		now, err := time.Parse(time.RFC3339, v.Now)
		if err != nil {
			t.Fatalf("%s: now %q: %v", v.Name, v.Now, err)
		}
		mode := ""
		if v.Mode != nil {
			mode = *v.Mode
		}
		got := Evaluate(Input{Mode: mode, OrgOperators: v.OrgOperators, Access: v.Access, Caller: v.Caller, Now: now})
		if got != v.Want {
			t.Errorf("%s: got %s, want %s", v.Name, got, v.Want)
		}
	}
}

// TestVectorsCoverEveryAnswer: the shared file names every answer of the
// rule, a missing mode, a device without a policy and Berlin's DST days,
// so a client that passes it has met each step.
func TestVectorsCoverEveryAnswer(t *testing.T) {
	seen := map[string]bool{}
	var nilMode, nilAccess, dstSpring, dstAutumn bool
	for _, v := range loadVectors(t) {
		seen[v.Want] = true
		nilMode = nilMode || v.Mode == nil
		nilAccess = nilAccess || v.Access == nil
		dstSpring = dstSpring || v.Now[:10] == "2026-03-29"
		dstAutumn = dstAutumn || v.Now[:10] == "2026-10-25"
	}
	for _, want := range []string{Allow, AskAlways, NotEnabled, OutsideSchedule, OperatorNotAllowed} {
		if !seen[want] {
			t.Errorf("no vector answers %s", want)
		}
	}
	if !nilMode || !nilAccess || !dstSpring || !dstAutumn {
		t.Errorf("missing mode %v, no policy %v, DST start %v, DST end %v: want all", nilMode, nilAccess, dstSpring, dstAutumn)
	}
}

// TestFromDB reads the comma lists the database keeps.
func TestFromDB(t *testing.T) {
	if FromDB(nil) != nil {
		t.Fatal("no row must be no policy")
	}
	a := FromDB(&db.AccessPolicy{UnattendedEnabled: true, ScheduleEnabled: true, ScheduleDays: "Mon, tue,,", ScheduleStartTime: "08:00",
		ScheduleEndTime: "18:00", ScheduleTimezone: "Europe/Berlin", AllowedOperators: " anna ,ben,"})
	if len(a.ScheduleDays) != 2 || a.ScheduleDays[0] != "mon" || a.ScheduleDays[1] != "tue" {
		t.Errorf("days %v", a.ScheduleDays)
	}
	if len(a.AllowedOperators) != 2 || a.AllowedOperators[0] != "anna" || a.AllowedOperators[1] != "ben" {
		t.Errorf("operators %v", a.AllowedOperators)
	}
	if a.ScheduleStart != "08:00" || a.ScheduleEnd != "18:00" || a.ScheduleTimezone != "Europe/Berlin" || !a.UnattendedEnabled || !a.ScheduleEnabled {
		t.Errorf("fields %+v", a)
	}
}

// TestOrgInputs reads the mode and the list from the policy answer and
// skips values of another type.
func TestOrgInputs(t *testing.T) {
	mode, ops := OrgInputs(map[string]any{
		"connection": map[string]any{"mode": "unattended"},
		"security":   map[string]any{"allowed_operators": []any{"anna", 3, "ben"}},
	})
	if mode != "unattended" || len(ops) != 2 || ops[0] != "anna" || ops[1] != "ben" {
		t.Errorf("got %q %v", mode, ops)
	}
	mode, ops = OrgInputs(map[string]any{"connection": map[string]any{"mode": 1}, "security": "x"})
	if mode != "" || len(ops) != 0 {
		t.Errorf("wrong types: got %q %v", mode, ops)
	}
}
