// Package unattended decides whether a vouched caller may reach a receiver
// without someone at the computer clicking Allow: the rule of the
// unattended access contract (lead/receiver-app/UNATTENDED-CONTRACT.md,
// A279). The server's caller check and the console's device page use this
// one function; the receiver app applies the same rule from its own copy
// of the policy, and testdata/rule-vectors.json holds the cases both sides
// must agree on.
package unattended

import (
	"regexp"
	"strings"
	"time"
	// Schedules name IANA zones; hosts without a zone database still know them
	_ "time/tzdata"

	"github.com/neodeskapp/neodesk/neodesk-server/db"
)

// The answers of Evaluate: Allow, or the reason of the refusal.
const (
	Allow              = "allow"
	AskAlways          = "ask_always"
	NotEnabled         = "not_enabled"
	OutsideSchedule    = "outside_schedule"
	OperatorNotAllowed = "operator_not_allowed"
)

// The organization's connection modes (policies.connection.mode).
const (
	ModeAttended   = "attended"
	ModeUnattended = "unattended"
	ModeAskAlways  = "ask_always"
)

// Access is a device's access policy as the rule reads it, and as the
// sealed heartbeat carries it (without password_set).
type Access struct {
	UnattendedEnabled bool     `json:"unattended_enabled"`
	ScheduleEnabled   bool     `json:"schedule_enabled"`
	ScheduleDays      []string `json:"schedule_days"`
	ScheduleStart     string   `json:"schedule_start"`
	ScheduleEnd       string   `json:"schedule_end"`
	ScheduleTimezone  string   `json:"schedule_timezone"`
	AllowedOperators  []string `json:"allowed_operators"`
}

// Input is what the rule decides on. Access nil is a device without an
// access policy; Mode "" is an organization without a connection mode.
type Input struct {
	Mode         string
	OrgOperators []string
	Access       *Access
	Caller       string
	Now          time.Time
}

// Evaluate applies the rule, first match wins:
//
//  1. mode ask_always: ask_always.
//  2. mode unattended: on to 4.
//  3. any other mode: the device's unattended_enabled must be on, else
//     not_enabled (also without an access policy).
//  4. schedule on: now in the schedule's time zone on a listed day, start
//     <= t < end; end before start runs over midnight and counts for the
//     day the window started on; start == end is the whole day. An
//     unknown time zone, a bad time or no days: outside_schedule.
//  5. operators: the caller is in the organization's list when it has
//     one, and in the device's list when it has one (trimmed, any case),
//     else operator_not_allowed.
//  6. Allow.
func Evaluate(in Input) string {
	switch strings.TrimSpace(in.Mode) {
	case ModeAskAlways:
		return AskAlways
	case ModeUnattended:
	default:
		if in.Access == nil || !in.Access.UnattendedEnabled {
			return NotEnabled
		}
	}
	if in.Access != nil && in.Access.ScheduleEnabled && !InSchedule(*in.Access, in.Now) {
		return OutsideSchedule
	}
	if !listed(in.OrgOperators, in.Caller) {
		return OperatorNotAllowed
	}
	if in.Access != nil && !listed(in.Access.AllowedOperators, in.Caller) {
		return OperatorNotAllowed
	}
	return Allow
}

// clock is a time of day as HH:MM in 24 hours.
var clock = regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)$`)

// minutes is HH:MM as minutes after midnight; ok is false for anything
// else.
func minutes(text string) (int, bool) {
	m := clock.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return 0, false
	}
	return int(m[1][0]-'0')*600 + int(m[1][1]-'0')*60 + int(m[2][0]-'0')*10 + int(m[2][1]-'0'), true
}

// days are the names of the weekdays as schedules list them, by
// time.Weekday.
var days = [7]string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// Zone is the IANA time zone name, nil when it is none: "", "Local" and
// names the zone database does not know.
func Zone(name string) *time.Location {
	name = strings.TrimSpace(name)
	if name == "" || name == "Local" {
		return nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil
	}
	return loc
}

// InSchedule reports whether now falls in the schedule of a (step 4),
// whether or not a's schedule is on.
func InSchedule(a Access, now time.Time) bool {
	loc := Zone(a.ScheduleTimezone)
	start, okStart := minutes(a.ScheduleStart)
	end, okEnd := minutes(a.ScheduleEnd)
	if loc == nil || !okStart || !okEnd {
		return false
	}
	listedDays := map[string]bool{}
	for _, d := range a.ScheduleDays {
		listedDays[strings.ToLower(strings.TrimSpace(d))] = true
	}
	local := now.In(loc)
	t := local.Hour()*60 + local.Minute()
	today := days[local.Weekday()]
	yesterday := days[(local.Weekday()+6)%7]
	switch {
	case start == end:
		return listedDays[today]
	case start < end:
		return listedDays[today] && start <= t && t < end
	case t >= start:
		return listedDays[today]
	case t < end:
		return listedDays[yesterday]
	}
	return false
}

// listed reports whether caller is in names, or names holds no name.
func listed(names []string, caller string) bool {
	caller = strings.ToLower(strings.TrimSpace(caller))
	named := false
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		named = true
		if n == caller {
			return true
		}
	}
	return !named
}

// List splits a comma-separated list as the database keeps them, without
// blanks.
func List(text string) []string {
	out := []string{}
	for _, part := range strings.Split(text, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// FromDB is the access policy of a database row, nil for none.
func FromDB(p *db.AccessPolicy) *Access {
	if p == nil {
		return nil
	}
	return &Access{
		UnattendedEnabled: p.UnattendedEnabled,
		ScheduleEnabled:   p.ScheduleEnabled,
		ScheduleDays:      List(strings.ToLower(p.ScheduleDays)),
		ScheduleStart:     p.ScheduleStartTime,
		ScheduleEnd:       p.ScheduleEndTime,
		ScheduleTimezone:  p.ScheduleTimezone,
		AllowedOperators:  List(p.AllowedOperators),
	}
}

// OrgInputs reads the organization's connection mode and allowed
// operators from its policies as GET /api/peers/{id}/policy answers them
// ({"connection": {"mode"}, "security": {"allowed_operators"}}). Values of
// another type count as missing.
func OrgInputs(policies map[string]any) (mode string, operators []string) {
	if connection, ok := policies["connection"].(map[string]any); ok {
		mode, _ = connection["mode"].(string)
	}
	if security, ok := policies["security"].(map[string]any); ok {
		if list, ok := security["allowed_operators"].([]any); ok {
			for _, item := range list {
				if name, ok := item.(string); ok {
					operators = append(operators, name)
				}
			}
		}
	}
	return mode, operators
}
