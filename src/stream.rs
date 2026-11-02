//! Events → numbered batches, plus the backlog `events_since` serves.
//!
//! Pure and synchronous: the caller decides when to tick and where batches
//! go. A batch is cut on count, on bytes, on a critical event (flushed at
//! once, `urgent`), or on the caller's timer.

use std::collections::VecDeque;

use virtsec_api::{
    Backlog, Batch, Counters, SecEvent, Severity, API_VERSION, MAX_BATCH_BYTES, MAX_BATCH_EVENTS,
};

/// Room kept under [`MAX_BATCH_BYTES`] for the batch's own fields.
const BATCH_OVERHEAD: usize = 4 * 1024;

/// Bytes of encoded batches the backlog holds at most, whatever
/// `backlog_events` says: the node runs other things.
const MAX_BACKLOG_BYTES: usize = 32 * 1024 * 1024;

/// A sent batch kept for `events_since`, encoded: a few hundred bytes an event
/// instead of the decoded strings, maps and JSON (about 6 KB an event).
#[derive(Debug)]
struct Held {
    seq: u64,
    events: usize,
    cbor: Vec<u8>,
}

#[derive(Debug)]
pub struct Stream {
    boot_id: String,
    node: String,
    seq: u64,
    pending: Vec<SecEvent>,
    pending_bytes: usize,
    pending_urgent: bool,
    dropped_since: u64,
    backlog: VecDeque<Held>,
    backlog_events: usize,
    backlog_bytes: usize,
    max_backlog_events: usize,
    max_backlog_bytes: usize,
    counters: Counters,
}

impl Stream {
    pub fn new(boot_id: String, node: String, max_backlog_events: usize) -> Self {
        Self {
            boot_id,
            node,
            seq: 0,
            pending: Vec::new(),
            pending_bytes: 0,
            pending_urgent: false,
            dropped_since: 0,
            backlog: VecDeque::new(),
            backlog_events: 0,
            backlog_bytes: 0,
            max_backlog_events: max_backlog_events.max(MAX_BATCH_EVENTS),
            max_backlog_bytes: MAX_BACKLOG_BYTES,
            counters: Counters::default(),
        }
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// Events the capture side had to drop (full queue).
    pub fn note_dropped(&mut self, n: u64) {
        self.dropped_since += n;
        self.counters.dropped += n;
    }

    /// Add one event; returns the batches to send now (a cut on size, or a
    /// critical event flushed with what was pending before it).
    pub fn push(&mut self, ev: SecEvent) -> Vec<Batch> {
        let size = virtsec_api::to_cbor(&ev).map(|b| b.len()).unwrap_or(0);
        if size + BATCH_OVERHEAD > MAX_BATCH_BYTES {
            // Can't ship it whole: count it, never send a frame the agent refuses.
            self.note_dropped(1);
            return Vec::new();
        }
        let mut out = Vec::new();
        if self.pending_bytes + size + BATCH_OVERHEAD > MAX_BATCH_BYTES {
            out.extend(self.flush());
        }
        self.pending_urgent |= ev.severity == Severity::Critical;
        self.pending.push(ev);
        self.pending_bytes += size;
        self.counters.events += 1;
        if self.pending_urgent || self.pending.len() >= MAX_BATCH_EVENTS {
            out.extend(self.flush());
        }
        out
    }

    /// Cut a batch from what is pending (timer). `None` when nothing is.
    pub fn flush(&mut self) -> Option<Batch> {
        if self.pending.is_empty() && self.dropped_since == 0 {
            return None;
        }
        self.seq += 1;
        let batch = Batch {
            api_version: API_VERSION,
            boot_id: self.boot_id.clone(),
            seq: self.seq,
            node: self.node.clone(),
            events: std::mem::take(&mut self.pending),
            dropped: std::mem::take(&mut self.dropped_since),
            urgent: std::mem::take(&mut self.pending_urgent),
        };
        self.pending_bytes = 0;
        self.counters.last_seq = self.seq;
        if let Ok(cbor) = virtsec_api::to_cbor(&batch) {
            self.backlog_events += batch.events.len();
            self.backlog_bytes += cbor.len();
            self.backlog.push_back(Held {
                seq: batch.seq,
                events: batch.events.len(),
                cbor,
            });
        }
        while self.backlog_events > self.max_backlog_events
            || self.backlog_bytes > self.max_backlog_bytes
        {
            match self.backlog.pop_front() {
                Some(old) => {
                    self.backlog_events -= old.events;
                    self.backlog_bytes -= old.cbor.len();
                }
                None => break,
            }
        }
        Some(batch)
    }

    /// The next held batch after `(boot_id, after_seq)`. Another `boot_id`
    /// (mlab knew the previous process) starts from the oldest held batch.
    pub fn since(&self, boot_id: &str, after_seq: u64) -> Backlog {
        let after = if boot_id == self.boot_id {
            after_seq
        } else {
            0
        };
        Backlog {
            boot_id: self.boot_id.clone(),
            batches: self
                .backlog
                .iter()
                .find(|h| h.seq > after)
                .and_then(|h| virtsec_api::from_cbor(&h.cbor).ok())
                .into_iter()
                .collect(),
            oldest_seq: self.backlog.front().map_or(self.seq + 1, |b| b.seq),
            last_seq: self.seq,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use virtsec_api::Source;

    fn ev(severity: Severity, msg: &str) -> SecEvent {
        SecEvent {
            source: Source::Ebpf,
            timestamp: 0,
            kind: "exec".into(),
            severity,
            guest: None,
            message: msg.into(),
            metadata: Default::default(),
            payload: serde_json::Value::Null,
        }
    }

    #[test]
    fn timer_cuts_and_seq_counts_up() {
        let mut s = Stream::new("b-1".into(), "n".into(), 10_000);
        assert!(s.push(ev(Severity::Info, "a")).is_empty());
        assert!(s.push(ev(Severity::Info, "b")).is_empty());
        let b = s.flush().unwrap();
        assert_eq!((b.seq, b.events.len(), b.urgent), (1, 2, false));
        assert!(s.flush().is_none(), "nothing pending");
        s.push(ev(Severity::Info, "c"));
        assert_eq!(s.flush().unwrap().seq, 2);
    }

    #[test]
    fn critical_flushes_at_once_in_order() {
        let mut s = Stream::new("b-1".into(), "n".into(), 10_000);
        s.push(ev(Severity::Info, "before"));
        let out = s.push(ev(Severity::Critical, "escape"));
        assert_eq!(out.len(), 1);
        assert!(out[0].urgent);
        let msgs: Vec<&str> = out[0].events.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(msgs, ["before", "escape"]);
    }

    #[test]
    fn cuts_on_count_and_bytes() {
        let mut s = Stream::new("b-1".into(), "n".into(), 100_000);
        let mut cut = Vec::new();
        for _ in 0..MAX_BATCH_EVENTS {
            cut.extend(s.push(ev(Severity::Info, "x")));
        }
        assert_eq!(cut.len(), 1);
        assert_eq!(cut[0].events.len(), MAX_BATCH_EVENTS);

        let big = "y".repeat(100 * 1024);
        let mut batches = Vec::new();
        for _ in 0..20 {
            batches.extend(s.push(ev(Severity::Info, &big)));
        }
        for b in &batches {
            assert!(virtsec_api::to_cbor(b).unwrap().len() <= MAX_BATCH_BYTES);
        }
        assert!(!batches.is_empty());
        // One event too big for any batch is dropped and counted, not sent.
        assert!(s
            .push(ev(Severity::Info, &"z".repeat(MAX_BATCH_BYTES)))
            .is_empty());
        assert_eq!(s.counters().dropped, 1);
    }

    #[test]
    fn backlog_serves_gaps_and_evicts_oldest() {
        let mut s = Stream::new("b-1".into(), "n".into(), MAX_BATCH_EVENTS);
        for i in 0..5 {
            for _ in 0..1000 {
                s.push(ev(Severity::Info, &i.to_string()));
            }
            s.flush();
        }
        // 5 batches of 1000, cap 2000 events: batches 4 and 5 remain.
        let b = s.since("b-1", 0);
        assert_eq!(b.oldest_seq, 4);
        assert_eq!(b.last_seq, 5);
        assert_eq!(b.batches[0].seq, 4);
        assert_eq!(s.since("b-1", 4).batches[0].seq, 5);
        assert!(s.since("b-1", 5).batches.is_empty());
        // mlab knew an older process: start from what this one holds.
        assert_eq!(s.since("b-0", 99).batches[0].seq, 4);
    }

    #[test]
    fn backlog_is_bounded_in_bytes_too() {
        let mut s = Stream::new("b-1".into(), "n".into(), 100_000);
        s.max_backlog_bytes = 1024 * 1024;
        let msg = "x".repeat(10 * 1024);
        for _ in 0..300 {
            s.push(ev(Severity::Info, &msg));
        }
        s.flush();
        assert!(s.backlog_bytes <= s.max_backlog_bytes);
        let b = s.since("b-1", 0);
        assert!(b.oldest_seq > 1, "the oldest batches were evicted");
        assert_eq!(b.batches[0].seq, b.oldest_seq);
        assert_eq!(b.batches[0].events[0].message, msg, "decoded intact");
    }

    #[test]
    fn drops_ride_the_next_batch() {
        let mut s = Stream::new("b-1".into(), "n".into(), 10_000);
        s.note_dropped(7);
        let b = s
            .flush()
            .expect("a batch carries the drop count even when empty");
        assert_eq!(b.dropped, 7);
        assert!(b.events.is_empty());
        assert_eq!(s.counters().dropped, 7);
    }
}
