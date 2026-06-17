use std::cmp::min;
use std::collections::VecDeque;

use bytes::Bytes;

use crate::byte_stream::ByteStream;
use crate::tcp_message::{TcpReceiverMessage, TcpSenderMessage};
use crate::wrapping_integers::Wrap32;

/// Configurable sender parameters.
///
/// `max_payload_size` is intentionally configurable instead of being hidden
/// in the implementation. This makes testing small segments easier and lets
/// an integration layer choose the payload size that fits its MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSenderConfig {
    /// Initial retransmission timeout.
    pub initial_rto_ms: u64,

    /// Upper bound for retransmission and persist exponential backoff.
    pub max_timer_interval_ms: u64,

    /// Maximum application payload placed in one segment.
    pub max_payload_size: usize,
}

impl Default for TcpSenderConfig {
    fn default() -> Self {
        Self {
            initial_rto_ms: 1_000,
            max_timer_interval_ms: 60_000,
            max_payload_size: 1_000,
        }
    }
}

/// Why the timer is currently running.
///
/// Retransmission and zero-window probing are deliberately separated:
///
/// - Retransmission timeout means the network may have lost a segment.
/// - Persist timeout means the receiver has advertised a zero window and
///   the sender periodically probes for reopening.
///
/// Both may resend the earliest outstanding segment, but only ordinary
/// retransmission increments `consecutive_retransmissions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerMode {
    Retransmission,
    Persist,
}

/// A deterministic timer driven entirely by `tick()`.
///
/// No operating-system clock is used. This keeps behavior testable.
#[derive(Debug, Default)]
struct Timer {
    running: bool,
    elapsed_ms: u64,
    timeout_ms: u64,
    mode: Option<TimerMode>,
}

impl Timer {
    fn restart(&mut self, timeout_ms: u64, mode: TimerMode) {
        debug_assert!(timeout_ms > 0);

        self.running = true;
        self.elapsed_ms = 0;
        self.timeout_ms = timeout_ms;
        self.mode = Some(mode);
    }

    fn stop(&mut self) {
        self.running = false;
        self.elapsed_ms = 0;
        self.timeout_ms = 0;
        self.mode = None;
    }

    fn tick(&mut self, elapsed_ms: u64) -> bool {
        if !self.running {
            return false;
        }

        self.elapsed_ms = self.elapsed_ms.saturating_add(elapsed_ms);

        self.elapsed_ms >= self.timeout_ms
    }

    fn timeout_ms(&self) -> Option<u64> {
        self.running.then_some(self.timeout_ms)
    }

    fn mode(&self) -> Option<TimerMode> {
        self.mode
    }
}

/// One segment that has been transmitted but not fully acknowledged.
///
/// The payload uses `Bytes`, so retransmission and partial-ACK trimming
/// normally share the original allocation.
#[derive(Debug, Clone)]
struct OutstandingSegment {
    absolute_start: u64,
    message: TcpSenderMessage,
}

impl OutstandingSegment {
    fn sequence_length(&self) -> u64 {
        self.message.sequence_length()
    }

    fn absolute_end(&self) -> u64 {
        self.absolute_start
            .checked_add(self.sequence_length())
            .expect("outstanding segment end overflowed")
    }

    /// Remove an acknowledged prefix while preserving the still-unacknowledged
    /// suffix.
    ///
    /// The prefix may consume SYN, payload bytes, and FIN in that order.
    fn trim_prefix(&mut self, acknowledged_length: u64, isn: Wrap32) {
        debug_assert!(acknowledged_length > 0);
        debug_assert!(acknowledged_length < self.sequence_length());

        let mut remaining = acknowledged_length;

        if self.message.syn && remaining > 0 {
            self.message.syn = false;
            remaining -= 1;
        }

        let payload_to_drop = min(remaining, self.message.payload.len() as u64) as usize;

        if payload_to_drop > 0 {
            self.message.payload = self.message.payload.slice(payload_to_drop..);

            remaining -= payload_to_drop as u64;
        }

        if self.message.fin && remaining > 0 {
            debug_assert_eq!(remaining, 1);

            self.message.fin = false;
            remaining -= 1;
        }

        debug_assert_eq!(remaining, 0);

        self.absolute_start = self
            .absolute_start
            .checked_add(acknowledged_length)
            .expect("trimmed segment start overflowed");

        self.message.seqno = Wrap32::wrap(self.absolute_start, isn);

        debug_assert!(!self.message.is_empty_in_sequence_space());
    }
}

/// Send-side state for one direction of a TCP connection.
///
/// This is stricter than the minimum Checkpoint 3 requirements:
///
/// - SND.UNA and SND.NXT are tracked explicitly;
/// - bytes in flight are derived from SND.NXT - SND.UNA;
/// - partially acknowledged segments are trimmed;
/// - zero-window probing uses a persist-style timer;
/// - retransmitted payloads reuse `Bytes` allocations.
#[derive(Debug)]
pub struct TcpSender {
    /// Bytes written by the local application but not yet segmented.
    outbound: ByteStream,

    /// Initial sequence number selected for this sender direction.
    isn: Wrap32,

    /// Oldest unacknowledged absolute sequence number.
    ///
    /// TCP name: SND.UNA.
    snd_una: u64,

    /// Next absolute sequence number to use for new data.
    ///
    /// TCP name: SND.NXT.
    snd_nxt: u64,

    /// Most recently accepted receiver-window advertisement.
    advertised_window: u64,

    /// Segments transmitted but not yet fully acknowledged.
    ///
    /// Sorted by sequence number because new segments are appended and ACKs
    /// advance from the front.
    outstanding: VecDeque<OutstandingSegment>,

    syn_sent: bool,
    fin_sent: bool,

    config: TcpSenderConfig,

    /// RTO used for ordinary packet-loss retransmission.
    current_rto_ms: u64,

    /// Timeout used while probing a receiver that advertises a zero window.
    persist_interval_ms: u64,

    timer: Timer,

    /// Ordinary loss retransmissions since the last advancing ACK.
    ///
    /// Persist probes do not increment this value.
    consecutive_retransmissions: u64,
}

impl TcpSender {
    pub fn new(capacity: usize, isn: Wrap32, config: TcpSenderConfig) -> Self {
        assert!(config.initial_rto_ms > 0, "initial RTO must be positive");

        assert!(
            config.max_timer_interval_ms >= config.initial_rto_ms,
            "maximum timer interval must not be smaller than initial RTO"
        );

        assert!(
            config.max_payload_size > 0,
            "maximum payload size must be positive"
        );

        Self {
            outbound: ByteStream::new(capacity),
            isn,
            snd_una: 0,
            snd_nxt: 0,

            // Before the peer advertises a window, Checkpoint 3 assumes one.
            advertised_window: 1,

            outstanding: VecDeque::new(),
            syn_sent: false,
            fin_sent: false,
            config,
            current_rto_ms: config.initial_rto_ms,
            persist_interval_ms: config.initial_rto_ms,
            timer: Timer::default(),
            consecutive_retransmissions: 0,
        }
    }

    pub fn outbound(&self) -> &ByteStream {
        &self.outbound
    }

    pub fn outbound_mut(&mut self) -> &mut ByteStream {
        &mut self.outbound
    }

    pub fn isn(&self) -> Wrap32 {
        self.isn
    }

    pub fn snd_una(&self) -> u64 {
        self.snd_una
    }

    pub fn snd_nxt(&self) -> u64 {
        self.snd_nxt
    }

    pub fn advertised_window(&self) -> u64 {
        self.advertised_window
    }

    /// Number of sequence numbers transmitted but not acknowledged.
    ///
    /// Deriving this from SND.NXT and SND.UNA avoids redundant state.
    pub fn bytes_in_flight(&self) -> u64 {
        self.snd_nxt
            .checked_sub(self.snd_una)
            .expect("SND.UNA cannot exceed SND.NXT")
    }

    pub fn outstanding_segments(&self) -> usize {
        self.outstanding.len()
    }

    pub fn consecutive_retransmissions(&self) -> u64 {
        self.consecutive_retransmissions
    }

    pub fn current_rto_ms(&self) -> u64 {
        self.current_rto_ms
    }

    pub fn persist_interval_ms(&self) -> u64 {
        self.persist_interval_ms
    }

    pub fn timer_timeout_ms(&self) -> Option<u64> {
        self.timer.timeout_ms()
    }

    pub fn timer_mode(&self) -> Option<&'static str> {
        match self.timer.mode() {
            Some(TimerMode::Retransmission) => Some("retransmission"),
            Some(TimerMode::Persist) => Some("persist"),
            None => None,
        }
    }

    pub fn syn_sent(&self) -> bool {
        self.syn_sent
    }

    pub fn fin_sent(&self) -> bool {
        self.fin_sent
    }

    /// True after FIN has been transmitted and fully acknowledged.
    pub fn is_finished(&self) -> bool {
        self.fin_sent && self.outstanding.is_empty()
    }

    /// Fill the receiver's advertised window with new segments.
    ///
    /// If the advertised window is zero, permit one sequence number as a
    /// zero-window probe. This is not stored as a fake permanent window.
    pub fn push<F>(&mut self, mut transmit: F)
    where
        F: FnMut(TcpSenderMessage),
    {
        let effective_window = self.advertised_window.max(1);

        while self.bytes_in_flight() < effective_window {
            let available_sequence_space = effective_window - self.bytes_in_flight();

            let mut message = self.make_empty_message();
            let mut remaining_sequence_space = available_sequence_space;

            if !self.syn_sent && remaining_sequence_space > 0 {
                message.syn = true;
                self.syn_sent = true;
                remaining_sequence_space -= 1;
            }

            let payload_budget = min(
                remaining_sequence_space as usize,
                self.config.max_payload_size,
            );

            message.payload = self.read_outbound_payload(payload_budget);

            remaining_sequence_space -= message.payload.len() as u64;

            if !self.fin_sent
                && self.outbound.is_closed()
                && self.outbound.bytes_buffered() == 0
                && remaining_sequence_space > 0
            {
                message.fin = true;
                self.fin_sent = true;
            }

            if message.is_empty_in_sequence_space() {
                break;
            }

            self.track_and_transmit(message, &mut transmit);
        }

        self.debug_check_invariants();
    }

    /// Process ACK and window feedback from the remote receiver.
    ///
    /// This method trims partially acknowledged outstanding segments.
    pub fn receive(&mut self, message: TcpReceiverMessage) {
        if message.rst {
            self.abort();
            return;
        }

        let new_window = message.window_size as u64;

        let Some(wrapped_ackno) = message.ackno else {
            let window_changed = self.advertised_window != new_window;

            self.advertised_window = new_window;

            if window_changed && !self.outstanding.is_empty() {
                self.restart_timer_for_current_window();
            }

            self.debug_check_invariants();
            return;
        };

        let absolute_ackno = wrapped_ackno.unwrap(self.isn, self.snd_nxt);

        // ACKing sequence numbers never transmitted is invalid.
        if absolute_ackno > self.snd_nxt {
            return;
        }

        let window_changed = self.advertised_window != new_window;

        self.advertised_window = new_window;

        let ack_advanced = absolute_ackno > self.snd_una;

        if ack_advanced {
            self.snd_una = absolute_ackno;
            self.discard_acknowledged_prefix();

            self.current_rto_ms = self.config.initial_rto_ms;
            self.persist_interval_ms = self.config.initial_rto_ms;
            self.consecutive_retransmissions = 0;
        }

        if self.outstanding.is_empty() {
            self.timer.stop();
        } else if ack_advanced || window_changed {
            self.restart_timer_for_current_window();
        }

        self.debug_check_invariants();
    }

    /// Advance deterministic time and retransmit the earliest outstanding
    /// segment when the active timer expires.
    pub fn tick<F>(&mut self, elapsed_ms: u64, mut transmit: F)
    where
        F: FnMut(TcpSenderMessage),
    {
        if !self.timer.tick(elapsed_ms) {
            return;
        }

        let Some(oldest) = self.outstanding.front() else {
            self.timer.stop();
            return;
        };

        transmit(oldest.message.clone());

        if self.advertised_window == 0 {
            // Persist probe:
            // do not treat a closed receive window as ordinary packet loss.
            self.persist_interval_ms = self.backed_off(self.persist_interval_ms);
        } else {
            // Ordinary retransmission timeout:
            // count consecutive retransmissions and back off RTO.
            self.consecutive_retransmissions = self.consecutive_retransmissions.saturating_add(1);

            self.current_rto_ms = self.backed_off(self.current_rto_ms);
        }

        self.restart_timer_for_current_window();

        self.debug_check_invariants();
    }

    /// Construct a segment that occupies no sequence space.
    ///
    /// It is useful when the integration layer needs a carrier for an ACK.
    /// Empty messages are not tracked as outstanding and are not retransmitted.
    pub fn make_empty_message(&self) -> TcpSenderMessage {
        TcpSenderMessage {
            seqno: Wrap32::wrap(self.snd_nxt, self.isn),
            syn: false,
            payload: Bytes::new(),
            fin: false,
            rst: self.outbound.has_error(),
        }
    }

    fn backed_off(&self, timeout_ms: u64) -> u64 {
        timeout_ms
            .saturating_mul(2)
            .min(self.config.max_timer_interval_ms)
    }

    /// Move application bytes out of ByteStream into one segment payload.
    fn read_outbound_payload(&mut self, max_len: usize) -> Bytes {
        if max_len == 0 {
            return Bytes::new();
        }

        let target_len = min(max_len, self.outbound.bytes_buffered());
        self.outbound.pop(target_len)
    }

    fn track_and_transmit<F>(&mut self, message: TcpSenderMessage, transmit: &mut F)
    where
        F: FnMut(TcpSenderMessage),
    {
        let sequence_length = message.sequence_length();

        debug_assert!(sequence_length > 0);

        let absolute_start = self.snd_nxt;

        self.snd_nxt = self
            .snd_nxt
            .checked_add(sequence_length)
            .expect("SND.NXT overflowed");

        let should_start_timer = self.outstanding.is_empty();

        self.outstanding.push_back(OutstandingSegment {
            absolute_start,
            message: message.clone(),
        });

        if should_start_timer {
            self.restart_timer_for_current_window();
        }

        transmit(message);
    }

    /// Remove complete ACKed segments and trim a partially ACKed front
    /// segment.
    fn discard_acknowledged_prefix(&mut self) {
        while self
            .outstanding
            .front()
            .is_some_and(|segment| segment.absolute_end() <= self.snd_una)
        {
            self.outstanding.pop_front();
        }

        if let Some(front) = self.outstanding.front_mut()
            && front.absolute_start < self.snd_una
        {
            let acknowledged_prefix = self.snd_una - front.absolute_start;

            front.trim_prefix(acknowledged_prefix, self.isn);
        }
    }

    fn restart_timer_for_current_window(&mut self) {
        if self.outstanding.is_empty() {
            self.timer.stop();
            return;
        }

        if self.advertised_window == 0 {
            self.timer
                .restart(self.persist_interval_ms, TimerMode::Persist);
        } else {
            self.timer
                .restart(self.current_rto_ms, TimerMode::Retransmission);
        }
    }

    fn abort(&mut self) {
        self.outbound.set_error();

        self.outstanding.clear();
        self.snd_una = self.snd_nxt;

        self.timer.stop();
    }

    fn debug_check_invariants(&self) {
        debug_assert!(self.snd_una <= self.snd_nxt);

        let mut previous_end = self.snd_una;

        for segment in &self.outstanding {
            debug_assert!(
                !segment.message.is_empty_in_sequence_space(),
                "empty segments must not be tracked as outstanding"
            );

            debug_assert!(
                segment.absolute_start >= previous_end,
                "outstanding segments must remain ordered and non-overlapping"
            );

            previous_end = segment.absolute_end();
        }

        if let Some(first) = self.outstanding.front() {
            debug_assert_eq!(
                first.absolute_start, self.snd_una,
                "first outstanding segment must begin at SND.UNA"
            );
        } else {
            debug_assert_eq!(
                self.snd_una, self.snd_nxt,
                "no outstanding segments implies no bytes in flight"
            );
        }

        debug_assert_eq!(self.bytes_in_flight(), self.snd_nxt - self.snd_una);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TcpSenderConfig {
        TcpSenderConfig {
            initial_rto_ms: 100,
            max_timer_interval_ms: 10_000,
            max_payload_size: 4,
        }
    }

    fn sender() -> TcpSender {
        TcpSender::new(64, Wrap32::new(1_000), config())
    }

    fn receiver_message(ackno: Option<u32>, window_size: u16) -> TcpReceiverMessage {
        TcpReceiverMessage {
            ackno: ackno.map(Wrap32::new),
            window_size,
            rst: false,
        }
    }

    #[test]
    fn first_push_sends_syn_only_with_default_window() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].seqno, Wrap32::new(1_000));
        assert!(sent[0].syn);
        assert!(sent[0].payload.is_empty());
        assert!(!sent[0].fin);

        assert_eq!(sender.snd_una(), 0);
        assert_eq!(sender.snd_nxt(), 1);
        assert_eq!(sender.bytes_in_flight(), 1);
        assert_eq!(sender.outstanding_segments(), 1);
        assert_eq!(sender.timer_mode(), Some("retransmission"));
    }

    #[test]
    fn no_duplicate_syn_on_second_push() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));
        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert_eq!(sender.bytes_in_flight(), 1);
        assert_eq!(sender.outstanding_segments(), 1);
    }

    #[test]
    fn empty_message_uses_next_sequence_number_and_is_not_tracked() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));

        let empty = sender.make_empty_message();

        assert_eq!(empty.seqno, Wrap32::new(1_001));
        assert!(empty.is_empty_in_sequence_space());
        assert_eq!(sender.outstanding_segments(), 1);
    }

    #[test]
    fn ack_of_syn_opens_window_and_stops_timer() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));

        sender.receive(receiver_message(Some(1_001), 8));

        assert_eq!(sender.snd_una(), 1);
        assert_eq!(sender.snd_nxt(), 1);
        assert_eq!(sender.bytes_in_flight(), 0);
        assert_eq!(sender.outstanding_segments(), 0);
        assert_eq!(sender.timer_timeout_ms(), None);
        assert_eq!(sender.advertised_window(), 8);
    }

    #[test]
    fn payload_is_segmented_and_fin_is_added_when_space_allows() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));
        sender.receive(receiver_message(Some(1_001), 8));

        assert_eq!(sender.outbound_mut().push(Bytes::from_static(b"abcdef")), 6);
        sender.outbound_mut().close();

        sent.clear();
        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 2);

        assert_eq!(sent[0].seqno, Wrap32::new(1_001));
        assert_eq!(sent[0].payload, Bytes::from_static(b"abcd"));
        assert!(!sent[0].syn);
        assert!(!sent[0].fin);

        assert_eq!(sent[1].seqno, Wrap32::new(1_005));
        assert_eq!(sent[1].payload, Bytes::from_static(b"ef"));
        assert!(!sent[1].syn);
        assert!(sent[1].fin);

        assert_eq!(sender.bytes_in_flight(), 7);
        assert_eq!(sender.outstanding_segments(), 2);
        assert!(sender.fin_sent());
    }

    #[test]
    fn fin_waits_for_window_space() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));
        sender.receive(receiver_message(Some(1_001), 4));

        sender.outbound_mut().push(Bytes::from_static(b"abcd"));
        sender.outbound_mut().close();

        sent.clear();
        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].payload, Bytes::from_static(b"abcd"));
        assert!(!sent[0].fin);
        assert!(!sender.fin_sent());

        sender.receive(receiver_message(Some(1_005), 4));

        sent.clear();
        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].seqno, Wrap32::new(1_005));
        assert!(sent[0].payload.is_empty());
        assert!(sent[0].fin);
        assert!(sender.fin_sent());
    }

    #[test]
    fn partial_ack_trims_front_segment_precisely() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));
        sender.receive(receiver_message(Some(1_001), 8));

        sender.outbound_mut().push(Bytes::from_static(b"abcdef"));
        sender.outbound_mut().close();

        sender.push(|message| sent.push(message));

        // ACK payload bytes 'a' and 'b', but not 'c' and 'd'.
        sender.receive(receiver_message(Some(1_003), 8));

        assert_eq!(sender.snd_una(), 3);
        assert_eq!(sender.bytes_in_flight(), 5);

        let front = sender.outstanding.front().unwrap();

        assert_eq!(front.absolute_start, 3);
        assert_eq!(front.message.seqno, Wrap32::new(1_003));
        assert_eq!(front.message.payload, Bytes::from_static(b"cd"));
        assert!(!front.message.syn);
        assert!(!front.message.fin);
    }

    #[test]
    fn partial_ack_can_trim_syn_and_payload_together() {
        let mut sender = TcpSender::new(
            64,
            Wrap32::new(5_000),
            TcpSenderConfig {
                initial_rto_ms: 100,
                max_timer_interval_ms: 10_000,
                max_payload_size: 10,
            },
        );

        sender.outbound_mut().push(Bytes::from_static(b"abc"));

        let mut sent = Vec::new();
        sender.receive(receiver_message(None, 10));
        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert!(sent[0].syn);
        assert_eq!(sent[0].payload, Bytes::from_static(b"abc"));

        // ACK SYN + 'a', leaving 'b' and 'c'.
        sender.receive(TcpReceiverMessage {
            ackno: Some(Wrap32::new(5_002)),
            window_size: 10,
            rst: false,
        });

        let front = sender.outstanding.front().unwrap();

        assert_eq!(front.absolute_start, 2);
        assert_eq!(front.message.seqno, Wrap32::new(5_002));
        assert!(!front.message.syn);
        assert_eq!(front.message.payload, Bytes::from_static(b"bc"));
    }

    #[test]
    fn ack_beyond_snd_nxt_is_ignored() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));

        sender.receive(receiver_message(Some(9_999), 10));

        assert_eq!(sender.snd_una(), 0);
        assert_eq!(sender.snd_nxt(), 1);
        assert_eq!(sender.bytes_in_flight(), 1);
        assert_eq!(sender.outstanding_segments(), 1);
    }

    #[test]
    fn duplicate_ack_updates_window_but_does_not_reset_rto() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));
        sender.tick(100, |_| {});

        assert_eq!(sender.current_rto_ms(), 200);
        assert_eq!(sender.consecutive_retransmissions(), 1);

        sender.receive(receiver_message(Some(1_000), 20));

        assert_eq!(sender.advertised_window(), 20);
        assert_eq!(sender.current_rto_ms(), 200);
        assert_eq!(sender.consecutive_retransmissions(), 1);
    }

    #[test]
    fn timeout_retransmits_earliest_segment_and_backs_off_rto() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));

        sent.clear();

        sender.tick(99, |message| sent.push(message));

        assert!(sent.is_empty());

        sender.tick(1, |message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert!(sent[0].syn);

        assert_eq!(sender.current_rto_ms(), 200);
        assert_eq!(sender.consecutive_retransmissions(), 1);
        assert_eq!(sender.timer_timeout_ms(), Some(200));
        assert_eq!(sender.timer_mode(), Some("retransmission"));
    }

    #[test]
    fn advancing_ack_resets_loss_backoff() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));
        sender.tick(100, |_| {});

        assert_eq!(sender.current_rto_ms(), 200);
        assert_eq!(sender.consecutive_retransmissions(), 1);

        sender.receive(receiver_message(Some(1_001), 10));

        assert_eq!(sender.current_rto_ms(), 100);
        assert_eq!(sender.consecutive_retransmissions(), 0);
        assert_eq!(sender.bytes_in_flight(), 0);
        assert_eq!(sender.timer_timeout_ms(), None);
    }

    #[test]
    fn rto_backoff_is_capped() {
        let mut sender = TcpSender::new(
            64,
            Wrap32::new(1_000),
            TcpSenderConfig {
                initial_rto_ms: 100,
                max_timer_interval_ms: 250,
                max_payload_size: 4,
            },
        );

        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));

        sender.tick(100, |_| {});
        assert_eq!(sender.current_rto_ms(), 200);

        sender.tick(200, |_| {});
        assert_eq!(sender.current_rto_ms(), 250);

        sender.tick(250, |_| {});
        assert_eq!(sender.current_rto_ms(), 250);
    }

    #[test]
    fn zero_window_allows_one_probe_and_uses_persist_backoff() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));

        sender.receive(receiver_message(Some(1_001), 0));

        sender.outbound_mut().push(Bytes::from_static(b"ABC"));

        sent.clear();
        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].seqno, Wrap32::new(1_001));
        assert_eq!(sent[0].payload, Bytes::from_static(b"A"));

        assert_eq!(sender.bytes_in_flight(), 1);
        assert_eq!(sender.timer_mode(), Some("persist"));

        sent.clear();
        sender.tick(100, |message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].payload, Bytes::from_static(b"A"));

        assert_eq!(sender.consecutive_retransmissions(), 0);
        assert_eq!(sender.persist_interval_ms(), 200);
        assert_eq!(sender.timer_timeout_ms(), Some(200));
        assert_eq!(sender.timer_mode(), Some("persist"));
    }

    #[test]
    fn opening_window_after_probe_allows_normal_sending() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));
        sender.receive(receiver_message(Some(1_001), 0));

        sender.outbound_mut().push(Bytes::from_static(b"ABC"));

        sent.clear();
        sender.push(|message| sent.push(message));

        assert_eq!(sent[0].payload, Bytes::from_static(b"A"));

        sender.receive(receiver_message(Some(1_002), 10));

        sent.clear();
        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].payload, Bytes::from_static(b"BC"));
        assert_eq!(sender.timer_mode(), Some("retransmission"));
        assert_eq!(sender.consecutive_retransmissions(), 0);
    }

    #[test]
    fn window_shrink_does_not_send_new_data_if_flight_exceeds_window() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));
        sender.receive(receiver_message(Some(1_001), 5));

        sender.outbound_mut().push(Bytes::from_static(b"ABCDE"));

        sent.clear();
        sender.push(|message| sent.push(message));

        assert_eq!(sender.bytes_in_flight(), 5);

        sender.receive(receiver_message(Some(1_001), 0));

        sent.clear();
        sender.push(|message| sent.push(message));

        assert!(sent.is_empty());
        assert_eq!(sender.bytes_in_flight(), 5);
    }

    #[test]
    fn rst_aborts_sender_and_clears_outstanding_queue() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));

        sender.receive(TcpReceiverMessage {
            ackno: None,
            window_size: 0,
            rst: true,
        });

        assert!(sender.outbound().has_error());
        assert_eq!(sender.bytes_in_flight(), 0);
        assert_eq!(sender.outstanding_segments(), 0);
        assert_eq!(sender.timer_timeout_ms(), None);
    }

    #[test]
    fn sender_finishes_after_fin_is_fully_acked() {
        let mut sender = sender();
        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));
        sender.receive(receiver_message(Some(1_001), 10));

        sender.outbound_mut().close();

        sent.clear();
        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert!(sent[0].fin);
        assert_eq!(sent[0].seqno, Wrap32::new(1_001));

        assert!(!sender.is_finished());

        sender.receive(receiver_message(Some(1_002), 10));

        assert!(sender.is_finished());
        assert_eq!(sender.bytes_in_flight(), 0);
        assert_eq!(sender.outstanding_segments(), 0);
    }

    #[test]
    fn sequence_number_wraparound_is_handled() {
        let mut sender = TcpSender::new(64, Wrap32::new(u32::MAX - 1), config());

        let mut sent = Vec::new();

        sender.push(|message| sent.push(message));

        assert_eq!(sent[0].seqno, Wrap32::new(u32::MAX - 1));
        assert!(sent[0].syn);

        sender.receive(TcpReceiverMessage {
            ackno: Some(Wrap32::new(u32::MAX)),
            window_size: 10,
            rst: false,
        });

        sender.outbound_mut().push(Bytes::from_static(b"cat"));
        sender.outbound_mut().close();

        sent.clear();
        sender.push(|message| sent.push(message));

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].seqno, Wrap32::new(u32::MAX));
        assert_eq!(sent[0].payload, Bytes::from_static(b"cat"));
        assert!(sent[0].fin);

        // SYN:
        //   seqno = u32::MAX - 1
        //
        // payload:
        //   c = u32::MAX
        //   a = 0
        //   t = 1
        //
        // FIN:
        //   2
        //
        // ACK after FIN:
        //   3
        sender.receive(TcpReceiverMessage {
            ackno: Some(Wrap32::new(3)),
            window_size: 10,
            rst: false,
        });

        assert!(sender.is_finished());
    }
}
