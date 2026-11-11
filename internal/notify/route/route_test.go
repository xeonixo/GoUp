package route

import (
	"testing"
	"time"
)

func TestParseEmpty(t *testing.T) {
	r, err := Parse(nil)
	if err != nil || len(r.Groups) != 0 || r.QuietHours != nil {
		t.Fatalf("empty parse = %+v err=%v", r, err)
	}
	r, err = Parse([]byte(`{}`))
	if err != nil || r.QuietHours != nil {
		t.Fatalf("object without route = %+v err=%v", r, err)
	}
	r, err = Parse([]byte(`{"route":null}`))
	if err != nil || len(r.Severities) != 0 {
		t.Fatalf("null route = %+v err=%v", r, err)
	}
}

func TestParseRoute(t *testing.T) {
	r, err := Parse([]byte(`{
		"url":"https://example.com",
		"route":{
			"groups":[" prod ", "prod"],
			"monitor_ids":[1,1,0,-2],
			"severities":["DOWN","reminder"],
			"quiet_hours":{"tz":"UTC","start":"22:00","end":"07:00","mode":"suppress"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Groups) != 1 || r.Groups[0] != "prod" {
		t.Fatalf("groups = %#v", r.Groups)
	}
	if len(r.MonitorIDs) != 1 || r.MonitorIDs[0] != 1 {
		t.Fatalf("monitor ids = %#v", r.MonitorIDs)
	}
	if !r.HasSeverity(SeverityDown) || !r.HasSeverity(SeverityReminder) {
		t.Fatalf("severities = %#v", r.Severities)
	}
	if r.QuietHours == nil || r.QuietHours.TZ != "UTC" || r.QuietHours.Mode != QuietModeSuppress {
		t.Fatalf("quiet hours = %+v", r.QuietHours)
	}
}

func TestSeverityOf(t *testing.T) {
	cases := []struct {
		prev, curr string
		reminder   bool
		want       string
	}{
		{"up", "down", false, SeverityDown},
		{"down", "up", false, SeverityRecovery},
		{"up", "degraded", false, SeverityDegraded},
		{"up", "unknown", false, SeverityDegraded},
		{"down", "down", true, SeverityReminder},
		{"down", "down", false, SeverityReminder},
		{"up", "down", true, SeverityReminder},
	}
	for _, tc := range cases {
		if got := SeverityOf(tc.prev, tc.curr, tc.reminder); got != tc.want {
			t.Errorf("SeverityOf(%q,%q,%v)=%q want %q", tc.prev, tc.curr, tc.reminder, got, tc.want)
		}
	}
}

func TestMatchesEmptyRoute(t *testing.T) {
	var r Route
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	if !r.Matches("any", 99, SeverityDown, now) {
		t.Fatal("empty route should match all")
	}
}

func TestMatchesGroupsOrMonitorIDs(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	r := Route{Groups: []string{"prod"}, MonitorIDs: []int64{7}}
	if !r.Matches("prod", 1, SeverityDown, now) {
		t.Fatal("expected group hit")
	}
	if !r.Matches("other", 7, SeverityDown, now) {
		t.Fatal("expected monitor id hit")
	}
	if r.Matches("other", 1, SeverityDown, now) {
		t.Fatal("expected miss when neither hits")
	}

	onlyGroup := Route{Groups: []string{"prod"}}
	if onlyGroup.Matches("staging", 1, SeverityDown, now) {
		t.Fatal("group-only should miss")
	}
	onlyID := Route{MonitorIDs: []int64{3}}
	if onlyID.Matches("prod", 2, SeverityDown, now) {
		t.Fatal("id-only should miss")
	}
}

func TestMatchesSeverities(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	r := Route{Severities: []string{SeverityDown, SeverityReminder}}
	if !r.Matches("", 1, SeverityDown, now) || !r.Matches("", 1, SeverityReminder, now) {
		t.Fatal("expected severity allow list hits")
	}
	if r.Matches("", 1, SeverityRecovery, now) {
		t.Fatal("expected severity miss")
	}
}

func TestQuietHoursSuppress(t *testing.T) {
	r := Route{QuietHours: &QuietHours{TZ: "UTC", Start: "22:00", End: "07:00", Mode: QuietModeSuppress}}
	inWindow := time.Date(2026, 5, 5, 23, 30, 0, 0, time.UTC)
	outWindow := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	if r.Matches("", 1, SeverityDown, inWindow) {
		t.Fatal("expected quiet hours suppress")
	}
	if !r.Matches("", 1, SeverityDown, outWindow) {
		t.Fatal("expected delivery outside quiet hours")
	}

	sameDay := Route{QuietHours: &QuietHours{TZ: "UTC", Start: "09:00", End: "17:00", Mode: QuietModeSuppress}}
	if sameDay.Matches("", 1, SeverityDown, time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC)) {
		t.Fatal("expected same-day quiet suppress")
	}
	if !sameDay.Matches("", 1, SeverityDown, time.Date(2026, 5, 5, 17, 0, 0, 0, time.UTC)) {
		t.Fatal("end boundary should not suppress")
	}
}

func TestQuietHoursUnsupportedModeIgnored(t *testing.T) {
	r := Route{QuietHours: &QuietHours{TZ: "UTC", Start: "00:00", End: "23:59", Mode: "delay"}}
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	if !r.Matches("", 1, SeverityDown, now) {
		t.Fatal("unsupported quiet mode must not suppress")
	}
}
