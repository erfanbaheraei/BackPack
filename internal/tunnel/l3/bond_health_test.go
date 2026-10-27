package l3

import (
	"strings"
	"testing"
	"time"
)

// healthClock drives one path's state machine by hand, at the cadence the
// control loop uses: evaluated every quarter interval, probed every quarter
// during discovery and every interval in service.
type healthClock struct {
	t     *testing.T
	h     bondHealth
	now   time.Time
	next  time.Time
	every time.Duration
}

func newHealthClock(t *testing.T) *healthClock {
	now := time.Unix(1_700_000_000, 0)
	return &healthClock{t: t, h: newBondHealth(now), now: now, next: now, every: time.Second}
}

// tick advances a quarter interval. A probe due now is sent and answered after
// rtt, unless lose says it is lost.
func (c *healthClock) tick(rtt time.Duration, lose func(seq uint64, full bool) bool) {
	if !c.now.Before(c.next) && c.h.state != bondDown {
		seq, full := c.h.nextProbe(c.now)
		if lose == nil || !lose(seq, full) {
			c.h.onAck(seq, c.now.Add(rtt))
		}
		every := c.every
		if c.h.state == bondProbing {
			every /= 4
		}
		c.next = c.now.Add(every)
	}
	c.now = c.now.Add(c.every / 4)
	c.h.evaluate(c.now, c.every)
}

func (c *healthClock) upAfter(ticks int) {
	for i := 0; i < ticks && c.h.state != bondUp; i++ {
		c.tick(20*time.Millisecond, nil)
	}
	if c.h.state != bondUp {
		c.t.Fatalf("path never entered service: %s (%s)", c.h.state, c.h.reason)
	}
}

func lostAll(uint64, bool) bool         { return true }
func lostFull(_ uint64, full bool) bool { return full }

func TestBondHealthQualifiesOnAnsweredProbes(t *testing.T) {
	c := newHealthClock(t)
	c.upAfter(bondUpAfter + 2)
	if c.h.srtt != 20*time.Millisecond {
		t.Fatalf("srtt %s, want 20ms", c.h.srtt)
	}
}

// Small probes answered and full-size ones not is a path that would carry ping
// and drop every large packet. It must not enter service, and must say why.
func TestBondHealthRequiresAFullSizeAnswer(t *testing.T) {
	c := newHealthClock(t)
	for i := 0; i < 8*bondDiscoveryRounds && c.h.state == bondProbing; i++ {
		c.tick(20*time.Millisecond, lostFull)
	}
	if c.h.state != bondDown {
		t.Fatalf("state %s, want down", c.h.state)
	}
	if !strings.Contains(c.h.reason, "MTU") {
		t.Fatalf("reason %q does not name the MTU", c.h.reason)
	}
}

// The case multipath cannot see: writes succeed, nothing comes back.
func TestBondHealthTakesASilentPathOut(t *testing.T) {
	c := newHealthClock(t)
	c.upAfter(10)
	start := c.now
	for i := 0; i < 80 && c.h.state == bondUp; i++ {
		c.tick(0, lostAll)
	}
	if c.h.state != bondDown || !strings.HasPrefix(c.h.reason, "silent") {
		t.Fatalf("state %s (%s), want down for silence", c.h.state, c.h.reason)
	}
	if took := c.now.Sub(start); took > bondMissedLimit*c.every+3*time.Second {
		t.Fatalf("a silent path took %s to notice", took)
	}
}

func TestBondHealthTakesALossyPathOut(t *testing.T) {
	c := newHealthClock(t)
	c.upAfter(10)
	// Two probes in three lost: the path still answers, so it is not silent,
	// but it is not worth carrying traffic on either.
	for i := 0; i < 16*bondLossWindow && c.h.state == bondUp; i++ {
		c.tick(20*time.Millisecond, func(seq uint64, _ bool) bool { return seq%3 != 0 })
	}
	if c.h.state != bondDown || !strings.HasPrefix(c.h.reason, "loss") {
		t.Fatalf("a path losing two probes in three is %s (%s), want down for loss", c.h.state, c.h.reason)
	}
}

// A flapping path is held out longer each time, up to the ceiling, and comes
// back through discovery — never straight into service.
func TestBondHealthBacksOffAndReprobes(t *testing.T) {
	h := newBondHealth(time.Unix(0, 0))
	now := time.Unix(0, 0)
	var last time.Duration
	for i := 0; i < 12; i++ {
		h.fail(now, "test")
		wait := h.retryAt.Sub(now)
		if wait < last || wait > bondBackoffMax {
			t.Fatalf("failure %d: backoff %s after %s", i+1, wait, last)
		}
		last = wait
	}
	if last != bondBackoffMax {
		t.Fatalf("backoff settled at %s, want the %s ceiling", last, bondBackoffMax)
	}
	h.evaluate(h.retryAt.Add(-time.Millisecond), time.Second)
	if h.state != bondDown {
		t.Fatal("the path was retried before its backoff ended")
	}
	h.evaluate(h.retryAt, time.Second)
	if h.state != bondProbing {
		t.Fatalf("after its backoff the path is %s, want probing", h.state)
	}
}

// An answer counts once, and only for a probe this path sent and is still
// waiting on — a replayed answer measures nothing.
func TestBondHealthCountsAnAnswerOnce(t *testing.T) {
	h := newBondHealth(time.Unix(0, 0))
	now := time.Unix(0, 0)
	seq, _ := h.nextProbe(now)
	if !h.onAck(seq, now.Add(time.Millisecond)) {
		t.Fatal("the first answer was refused")
	}
	if h.onAck(seq, now.Add(2*time.Millisecond)) {
		t.Fatal("a replayed answer was counted")
	}
	if h.onAck(seq+1, now) || h.onAck(seq+bondOutstanding, now) {
		t.Fatal("an answer to a probe never sent was counted")
	}
}

// A score moves only once the measurement has disagreed with it by 15% for
// three evaluations in a row.
func TestBondHealthScoreHasHysteresis(t *testing.T) {
	h := bondHealth{score: 100}
	h.hasRTT, h.srtt = true, 110*time.Millisecond // 10% off: never moves it
	for i := 0; i < 10; i++ {
		h.filterScore()
	}
	if h.score != 100 {
		t.Fatalf("a 10%% change moved the score to %.1f", h.score)
	}
	h.srtt = 130 * time.Millisecond // 30% off
	h.filterScore()
	h.filterScore()
	if h.score != 100 {
		t.Fatal("the score moved before three rounds")
	}
	h.filterScore()
	if h.score != 130 {
		t.Fatalf("after three rounds the score is %.1f, want 130", h.score)
	}
}
