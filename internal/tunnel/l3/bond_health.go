package l3

import (
	"fmt"
	"math"
	"time"
)

// One path's health, as the bond's probes measure it (ADR 0006, D3/D4/D6).
//
// A path is in one of three states:
//
//	probing  being measured before it carries anything (discovery)
//	up       in service: the scheduler may put traffic on it
//	down     failed, held out until a backoff passes, then probed again
//
// Nothing here touches a socket or a clock of its own: every method is given
// the time, so the state machine can be driven step by step in a test.

type bondState int

const (
	bondProbing bondState = iota
	bondUp
	bondDown
)

func (s bondState) String() string {
	switch s {
	case bondProbing:
		return "probing"
	case bondUp:
		return "up"
	case bondDown:
		return "down"
	}
	return "unknown"
}

const (
	// bondUpAfter is how many answered probes in a row a path needs before it
	// carries traffic. One could be luck; three is a path.
	bondUpAfter = 3

	// bondMissedLimit is how many probe intervals an in-service path may go
	// without any answer before it is taken out. This is the silent-failure
	// detector: it fires while writes to the path still succeed.
	bondMissedLimit = 3

	// bondLossWindow is how many recent probes the loss figure is taken over,
	// and bondMaxLoss the loss at which a path that still answers sometimes is
	// taken out anyway.
	bondLossWindow = 20
	bondMaxLoss    = 0.5

	// bondFullEvery: one probe in this many, once in service, is padded to the
	// largest datagram the tunnel sends, so a path whose MTU shrinks is found.
	// bondFullMissLimit full-size probes lost in a row, while the small ones are
	// answered, takes the path out: it would carry ping and drop every large
	// packet, the black hole the engine warns about.
	bondFullEvery     = 10
	bondFullMissLimit = 3

	// Backoff before a failed path is probed again. It doubles on each failure
	// in a row, so a flapping path is held out longer each time, and resets
	// once a path has stayed up for bondStableAfter.
	//
	// ADR 0006 sketched 30 s as the first step; 5 s is used instead because the
	// commonest failure is a short blip, and a path that was down for two
	// seconds should not be idle for thirty. The doubling still reaches the
	// five-minute ceiling after seven failures in a row.
	bondBackoffMin  = 5 * time.Second
	bondBackoffMax  = 5 * time.Minute
	bondStableAfter = time.Minute

	// bondDiscoveryRounds bounds discovery: a path that has not qualified
	// within this many probe intervals is called down, with the reason.
	bondDiscoveryRounds = 8

	// Anti-flap for the scheduler's weights: a path's score is taken as
	// changed only once the measurement has differed from it by this much for
	// this many evaluations in a row — the reverse engine's rule
	// (healthscore.go).
	bondHysteresis       = 0.15
	bondHysteresisRounds = 3

	// bondOutstanding is how many unanswered probes a path remembers.
	bondOutstanding = 64
)

// bondSent is one probe awaiting its answer.
type bondSent struct {
	seq   uint64
	at    time.Time
	full  bool
	acked bool
	done  bool // answered or given up on; counted either way
}

// bondHealth is guarded by its bondPath's mutex.
type bondHealth struct {
	state  bondState
	reason string
	since  time.Time

	retryAt  time.Time
	failures int

	streak int  // answered probes in a row, during discovery
	fullOK bool // a full-size probe was answered during this discovery

	fullMiss int // full-size probes lost in a row while in service

	seq     uint64
	ring    [bondOutstanding]bondSent
	lastAck time.Time

	srtt    time.Duration
	jitter  time.Duration
	prevRTT time.Duration
	hasRTT  bool

	window  [bondLossWindow]bool // true = lost
	wIdx    int
	wFilled int

	// The score the scheduler weighs by, after hysteresis, and the run of
	// evaluations the measurement has disagreed with it.
	score       float64
	scoreStreak int
}

// newBondHealth starts a path in discovery.
func newBondHealth(now time.Time) bondHealth {
	return bondHealth{state: bondProbing, since: now, reason: "discovering"}
}

// nextProbe allocates the next probe and reports whether it is to be padded to
// full size. During discovery every other probe is, so a path cannot qualify
// without proving its MTU; in service, one in bondFullEvery.
func (h *bondHealth) nextProbe(now time.Time) (seq uint64, full bool) {
	h.seq++
	seq = h.seq
	if h.state == bondProbing {
		full = seq%2 == 0
	} else {
		full = seq%bondFullEvery == 0
	}
	h.ring[seq%bondOutstanding] = bondSent{seq: seq, at: now, full: full}
	return seq, full
}

// onAck records an answer. It returns false for an answer to a probe this path
// never sent, already counted, or has given up on — which includes every
// replayed answer.
func (h *bondHealth) onAck(seq uint64, now time.Time) bool {
	s := &h.ring[seq%bondOutstanding]
	if s.seq != seq || s.seq == 0 || s.done {
		return false
	}
	s.acked, s.done = true, true
	rtt := now.Sub(s.at)
	if rtt < 0 {
		rtt = 0
	}
	if !h.hasRTT {
		h.srtt, h.prevRTT, h.hasRTT = rtt, rtt, true
	} else {
		// RFC 6298 smoothing for the mean, RFC 3550 for the jitter.
		h.srtt += (rtt - h.srtt) / 8
		d := rtt - h.prevRTT
		if d < 0 {
			d = -d
		}
		h.jitter += (d - h.jitter) / 16
		h.prevRTT = rtt
	}
	h.lastAck = now
	h.record(false)
	h.streak++
	if s.full {
		h.fullOK = true
		h.fullMiss = 0
	}
	return true
}

// timeout is how long a probe is waited for before it is counted lost.
func (h *bondHealth) timeout() time.Duration {
	if !h.hasRTT {
		return 2 * time.Second
	}
	t := 3*h.srtt + 4*h.jitter
	return min(max(t, 500*time.Millisecond), 3*time.Second)
}

// expire counts every probe that has waited out its timeout as lost.
func (h *bondHealth) expire(now time.Time) {
	limit := h.timeout()
	for i := range h.ring {
		s := &h.ring[i]
		if s.seq == 0 || s.done || now.Sub(s.at) < limit {
			continue
		}
		s.done = true
		h.record(true)
		h.streak = 0
		if s.full && h.state == bondUp {
			h.fullMiss++
		}
	}
}

func (h *bondHealth) record(lost bool) {
	h.window[h.wIdx] = lost
	h.wIdx = (h.wIdx + 1) % bondLossWindow
	if h.wFilled < bondLossWindow {
		h.wFilled++
	}
}

// loss is the fraction of the recent window that went unanswered.
func (h *bondHealth) loss() float64 {
	if h.wFilled == 0 {
		return 0
	}
	n := 0
	for i := 0; i < h.wFilled; i++ {
		if h.window[i] {
			n++
		}
	}
	return float64(n) / float64(h.wFilled)
}

// measuredScore is healthscore.go's formula — rtt + 2·jitter + 20·loss%, in
// milliseconds, lower is better — so the two engines rank paths the same way.
func (h *bondHealth) measuredScore() float64 {
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	return ms(h.srtt) + 2*ms(h.jitter) + 20*100*h.loss()
}

// evaluate advances the state machine. It returns whether the state changed,
// so the caller can say so and rebuild the schedule.
func (h *bondHealth) evaluate(now time.Time, every time.Duration) bool {
	h.expire(now)
	switch h.state {
	case bondProbing:
		if h.streak >= bondUpAfter && h.fullOK {
			h.enter(bondUp, now, "answering")
			h.score, h.scoreStreak = h.measuredScore(), 0
			return true
		}
		if now.Sub(h.since) > bondDiscoveryRounds*every+h.timeout() {
			reason := "no probe answered"
			if h.hasRTT && !h.fullOK {
				reason = "small probes answered, full-size ones not: the path's MTU is too small"
			}
			h.fail(now, reason)
			return true
		}
	case bondUp:
		silentFor := now.Sub(h.lastAck)
		switch {
		case silentFor > bondMissedLimit*every+h.timeout():
			h.fail(now, fmt.Sprintf("silent: no probe answered for %s", silentFor.Round(time.Millisecond)))
			return true
		case h.wFilled >= bondLossWindow/2 && h.loss() >= bondMaxLoss:
			h.fail(now, fmt.Sprintf("loss %.0f%%", 100*h.loss()))
			return true
		case h.fullMiss >= bondFullMissLimit:
			h.fail(now, "full-size probes lost while small ones are answered: the path's MTU shrank")
			return true
		}
		if h.failures > 0 && now.Sub(h.since) >= bondStableAfter {
			h.failures = 0
		}
		h.filterScore()
	case bondDown:
		if !now.Before(h.retryAt) {
			h.enter(bondProbing, now, "re-probing")
			return true
		}
	}
	return false
}

// fail takes the path out and schedules its next try.
func (h *bondHealth) fail(now time.Time, reason string) {
	h.failures++
	backoff := bondBackoffMin << min(h.failures-1, 16)
	if backoff > bondBackoffMax || backoff <= 0 {
		backoff = bondBackoffMax
	}
	h.retryAt = now.Add(backoff)
	h.enter(bondDown, now, reason)
}

// enter switches state and clears what the new state measures afresh. The
// RTT history is kept: it is still the best guess at the path's timing.
func (h *bondHealth) enter(s bondState, now time.Time, reason string) {
	h.state, h.since, h.reason = s, now, reason
	h.streak, h.fullOK, h.fullMiss = 0, false, 0
	if s != bondUp {
		h.wIdx, h.wFilled = 0, 0
	}
	if s == bondProbing {
		// Probes sent before the path went down must not count towards it
		// coming back.
		for i := range h.ring {
			h.ring[i].done = true
		}
	}
}

// filterScore applies the anti-flap rule to the score the scheduler weighs by.
func (h *bondHealth) filterScore() {
	m := h.measuredScore()
	if h.score <= 0 {
		h.score, h.scoreStreak = m, 0
		return
	}
	if math.Abs(m-h.score)/h.score >= bondHysteresis {
		h.scoreStreak++
		if h.scoreStreak >= bondHysteresisRounds {
			h.score, h.scoreStreak = m, 0
		}
		return
	}
	h.scoreStreak = 0
}
