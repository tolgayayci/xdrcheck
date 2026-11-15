package main

// The date-aware and network-state parts of `xdrcheck pins check`.
//
// Offline, always: every pins.toml [[schedule]] event is read against today's date (UTC, or --today). From 14
// days before the event's day the check warns; on the day it warns; after the day, if the event's pin still
// holds the value it had before the event, the check fails and prints the event's action. A testnet reset
// therefore turns the check red the day after it happens until public_lake.testnet moves, and a mainnet vote
// until protocol.network_mainnet does.
//
// With --network (the nightly network-state job; never in a pull request's offline run), read-only GETs of:
//   - the Horizon root of mainnet and testnet: current_protocol_version is compared with
//     protocol.network_<net> (a difference warns: the pin is stale) and with protocol.max_supported (above it
//     fails: the network runs a protocol the kit does not cover, see docs/maintenance.md section 5.2);
//     core_supported_protocol_version above current_protocol_version is reported (validators are ready for
//     an upgrade vote). Testnet's latest ledger below the highest ledger vendored from the pinned epoch means
//     testnet has been reset: that fails.
//   - the status page's scheduled maintenances: a protocol upgrade or network reset there whose date is not
//     a [[schedule]] event warns (record it), and a [[schedule]] event less than 10 days away that the status
//     page does not list warns (the status page usually announces two weeks ahead; confirm the date).
// A source that cannot be read is a failure: the job exists to read them.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/pins"
)

// Read-only public endpoints of the network-state check.
const (
	horizonMainnet  = "https://horizon.stellar.org/"
	horizonTestnet  = "https://horizon-testnet.stellar.org/"
	statusUpcoming  = "https://status.stellar.org/api/v2/scheduled-maintenances/upcoming.json"
	warnBeforeDays  = 14 // a schedule event warns from this many days before its day
	unannouncedDays = 10 // an event this close and not on the status page warns
)

// watchSources are the endpoints the network check reads; tests point them at a local server.
type watchSources struct {
	horizon map[string]string // network name (mainnet, testnet) -> Horizon root URL
	status  string            // the status page's upcoming scheduled maintenances (JSON)
	client  *http.Client
}

func defaultWatchSources() *watchSources {
	return &watchSources{
		horizon: map[string]string{"mainnet": horizonMainnet, "testnet": horizonTestnet},
		status:  statusUpcoming,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *pinsChecker) warnf(format string, a ...any) {
	c.warnings++
	fmt.Fprintf(c.out, "warn "+format+"\n", a...)
}

// todayUTC is the date the schedule is read against: --today, else the clock.
func (c *pinsChecker) todayUTC() time.Time {
	t := c.today
	if t.IsZero() {
		t = time.Now()
	}
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// schedule checks every [[schedule]] event against today's date.
func (c *pinsChecker) schedule() {
	today := c.todayUTC()
	for _, e := range c.p.Schedule {
		day, _ := e.Day() // validated when pins.toml was read
		have, _ := c.p.Value(e.Pin)
		days := int(day.Sub(today).Hours() / 24)
		c.checks++
		switch {
		case have != e.Until:
			c.infof("schedule: %s (%s): %s is %s, no longer %s; remove the event from pins.toml once nothing else needs it", e.Event, e.Date, e.Pin, have, e.Until)
		case days < 0:
			c.drifts++
			fmt.Fprintf(c.out, "FAIL schedule: %s was on %s (%d day(s) ago) and %s still is %s: %s (source: %s)\n",
				e.Event, e.Date, -days, e.Pin, have, e.Action, e.Source)
		case days == 0:
			c.warnf("schedule: %s is today (%s); afterwards: %s", e.Event, e.Date, e.Action)
		case days <= warnBeforeDays:
			c.warnf("schedule: %s in %d day(s), on %s; afterwards: %s", e.Event, days, e.Date, e.Action)
		default:
			c.infof("schedule: %s in %d day(s), on %s", e.Event, days, e.Date)
		}
	}
}

// ---- --network ----

type horizonRoot struct {
	CurrentProtocolVersion       *int   `json:"current_protocol_version"`
	CoreSupportedProtocolVersion *int   `json:"core_supported_protocol_version"`
	CoreLatestLedger             *int64 `json:"core_latest_ledger"`
	CoreVersion                  string `json:"core_version"`
	NetworkPassphrase            string `json:"network_passphrase"`
}

type statusMaintenance struct {
	Name         string `json:"name"`
	ScheduledFor string `json:"scheduled_for"`
	Shortlink    string `json:"shortlink"`
}

func (s *watchSources) getJSON(url string, v any) error {
	resp, err := s.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("GET %s: %v", url, err)
	}
	return nil
}

var networkPassphrases = map[string]string{
	"mainnet": "Public Global Stellar Network ; September 2015",
	"testnet": "Test SDF Network ; September 2015",
}

// network runs the --network checks.
func (c *pinsChecker) network() {
	src := c.sources
	if src == nil {
		src = defaultWatchSources()
	}
	for _, net := range []string{"mainnet", "testnet"} {
		c.horizon(src, net)
	}
	c.statusPage(src)
}

func (c *pinsChecker) horizon(src *watchSources, net string) {
	url := src.horizon[net]
	var r horizonRoot
	if err := src.getJSON(url, &r); err != nil {
		c.failf("network %s: Horizon root not read: %v", net, err)
		return
	}
	if r.CurrentProtocolVersion == nil || r.CoreSupportedProtocolVersion == nil {
		c.failf("network %s: %s has no current_protocol_version or core_supported_protocol_version", net, url)
		return
	}
	c.checks++
	if r.NetworkPassphrase != networkPassphrases[net] {
		c.drifts++
		fmt.Fprintf(c.out, "FAIL network %s: %s serves passphrase %q, not %q\n", net, url, r.NetworkPassphrase, networkPassphrases[net])
		return
	}
	cur, sup := *r.CurrentProtocolVersion, *r.CoreSupportedProtocolVersion
	pinKey := "protocol.network_" + net
	pinned, _ := c.p.Value(pinKey)
	ceiling := c.p.Protocol.MaxSupported
	c.infof("network %s: protocol %d, validators' core supports %d (%s)", net, cur, sup, r.CoreVersion)
	c.checks++
	switch {
	case cur > ceiling:
		c.drifts++
		fmt.Fprintf(c.out, "FAIL network %s runs protocol %d, above protocol.max_supported %d: capture and mine read its ledgers with a warning; start the upgrade (docs/maintenance.md, section 5.2 if no XDR changed, else section 5)\n", net, cur, ceiling)
	case strconv.Itoa(cur) != pinned:
		c.warnf("network %s runs protocol %d, pins.toml %s is %s: update the pin (and any [[schedule]] event for it)", net, cur, pinKey, pinned)
	}
	if sup > cur {
		if sup > ceiling {
			c.warnf("network %s: validators run a core that supports protocol %d, above protocol.max_supported %d; an upgrade vote can follow", net, sup, ceiling)
		} else {
			c.infof("network %s: validators are ready for protocol %d; an upgrade vote can follow", net, sup)
		}
	}
	if net == "testnet" && r.CoreLatestLedger != nil {
		c.testnetReset(*r.CoreLatestLedger)
	}
}

// testnetReset compares testnet's latest ledger with the highest ledger the corpus vendored from the pinned
// testnet epoch: a network whose sequence is below it has been reset since.
func (c *pinsChecker) testnetReset(latest int64) {
	epoch := c.p.PublicLake.Testnet
	records, _ := filepath.Glob(filepath.Join(c.root, "corpus", "objects", "testnet", "*", "capture.json"))
	var highest int64
	for _, rec := range records {
		data, err := os.ReadFile(rec)
		if err != nil {
			continue
		}
		var r struct {
			Store     string `json:"store"`
			LedgerSeq int64  `json:"ledger_seq"`
		}
		if json.Unmarshal(data, &r) != nil || !strings.HasSuffix(strings.TrimSuffix(r.Store, "/"), "/"+epoch) {
			continue
		}
		highest = max(highest, r.LedgerSeq)
	}
	if highest == 0 {
		c.infof("network testnet: no ledger vendored from epoch %s; the reset check has nothing to compare", epoch)
		return
	}
	c.checks++
	if latest < highest {
		c.drifts++
		fmt.Fprintf(c.out, "FAIL network testnet: latest ledger %d is below ledger %d vendored from epoch %s: testnet has been reset; move public_lake.testnet to the new epoch and run `xdrcheck-corpus refetch --network testnet` (docs/maintenance.md, section 8)\n", latest, highest, epoch)
		return
	}
	c.infof("network testnet: latest ledger %d, above ledger %d vendored from epoch %s: no reset since", latest, highest, epoch)
}

// statusRelevant matches the status page maintenances the pins depend on.
var statusRelevant = regexp.MustCompile(`(?i)protocol upgrade|upgrade vote|reset`)

func (c *pinsChecker) statusPage(src *watchSources) {
	var page struct {
		ScheduledMaintenances []statusMaintenance `json:"scheduled_maintenances"`
	}
	if err := src.getJSON(src.status, &page); err != nil {
		c.failf("network: status page not read: %v", err)
		return
	}
	announced := map[string]bool{}
	for _, m := range page.ScheduledMaintenances {
		t, err := time.Parse(time.RFC3339, m.ScheduledFor)
		if err != nil || !statusRelevant.MatchString(m.Name) {
			continue
		}
		day := t.UTC().Format(pins.DateLayout)
		announced[day] = true
		c.checks++
		known := false
		for _, e := range c.p.Schedule {
			known = known || e.Date == day
		}
		if known {
			c.infof("status page: %q on %s is a [[schedule]] event", m.Name, day)
		} else {
			c.warnf("status page announces %q on %s (%s), which is not a pins.toml [[schedule]] event: record it with the pin it changes", m.Name, t.UTC().Format(time.RFC3339), m.Shortlink)
		}
	}
	today := c.todayUTC()
	for _, e := range c.p.Schedule {
		day, _ := e.Day()
		days := int(day.Sub(today).Hours() / 24)
		if have, _ := c.p.Value(e.Pin); have != e.Until || days < 0 || announced[e.Date] {
			continue
		}
		if days <= unannouncedDays {
			c.warnf("schedule: %s on %s is %d day(s) away and not on the status page; confirm the date (source: %s)", e.Event, e.Date, days, e.Source)
		}
	}
}
