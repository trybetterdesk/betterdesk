package policies

import (
	"testing"

	"github.com/neodeskapp/neodesk/neodesk-server/api"
)

// TestReceiverAppliesNamesRealSettings: every setting the console says the
// receiver app applies is a setting of that group, so a renamed setting
// can't leave the console naming one that no longer exists.
func TestReceiverAppliesNamesRealSettings(t *testing.T) {
	fields := map[string]map[string]bool{}
	for _, group := range api.PolicyFields() {
		fields[group.Group] = map[string]bool{}
		for _, name := range group.Fields {
			fields[group.Group][name] = true
		}
	}
	for group, names := range receiverApplies {
		if serverGroups[group] {
			t.Errorf("%s is applied by the server, not by the receiver app", group)
		}
		for _, name := range names {
			if !fields[group][name] {
				t.Errorf("receiverApplies names %s.%s, which is no policy setting", group, name)
			}
		}
	}
}

// TestReceiverAppliesTheAllowedOperators: the receiver app and the
// server's caller check apply the organization's allowed operators to
// unattended callers (A279), so the policy page says so.
func TestReceiverAppliesTheAllowedOperators(t *testing.T) {
	found := false
	for _, name := range receiverApplies["security"] {
		found = found || name == "allowed_operators"
	}
	if !found {
		t.Fatalf("receiverApplies security %v, want allowed_operators among them", receiverApplies["security"])
	}
}
