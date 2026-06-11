use std::cmp::min;

use crate::reassembler::{Reassembler, ReassemblerError};
use crate::tcp_message::{TcpReceiverMessage, TcpSenderMessage};
use crate::wrapping_integers::Wrap32;

#[derive(Debug)]
pub struct TcpReceiver{
    reassembler: Reassembler,
    isn:Option<Wrap32>,
}

impl TcpReceiver{
    pub fn new(capacity:usize)-> Self{
        Self { reassembler: Reassembler::new(capacity), isn: None }
    }

    pub fn reassembler(&self) -> &Reassembler {
        &self.reassembler
    }

    pub fn reassembler_mut(&mut self) -> &mut Reassembler {
        &mut self.reassembler
    }

    pub fn output(&self)-> &crate::byte_stream::ByteStream{
        self.reassembler.output()
    }

    pub fn output_mut(&mut self)-> &mut crate::byte_stream::ByteStream{
        self.reassembler.output_mut()
    }

    pub fn receive(&mut self, message:TcpSenderMessage)->Result<(), ReassemblerError>{
        if message.rst{
            self.reassembler.output_mut().set_error();
            return Ok(())
        }

        let isn=match self.isn{
            Some(isn)=>{
                if message.syn&&message.seqno!=isn{
                    return Ok(())
                }
                isn
            }
            None=>{
                if !message.syn{
                    return Ok(())
                }
                self.isn=Some(message.seqno);
                message.seqno
            }
        };

        let checkpoint=self
            .reassembler
            .output()
            .bytes_pushed()
            .saturating_add(1);

        let absolute_seqno=message.seqno.unwrap(isn, checkpoint);

        let stream_index=if message.syn{
            absolute_seqno
        }else{
            let Some(index)=absolute_seqno.checked_sub(1) else{
                return Ok(());
            };
            index
        };

        self.reassembler.try_insert(stream_index, &message.payload, message.fin)?;

        Ok(())

    }

    pub fn send(&self) -> TcpReceiverMessage {
        let ackno = self.isn.map(|isn| {
            // SYN consumes one sequence number.
            let mut absolute_ackno = self
                .reassembler
                .output()
                .bytes_pushed()
                .saturating_add(1);

            // Once Reassembler has assembled through FIN, ByteStream is
            // closed and FIN consumes one additional sequence number.
            if self.reassembler.output().is_closed() {
                absolute_ackno = absolute_ackno.saturating_add(1);
            }

            Wrap32::wrap(absolute_ackno, isn)
        });

        let available_capacity =
            self.reassembler.output().available_capacity();

        let window_size = min(available_capacity, u16::MAX as usize) as u16;

        TcpReceiverMessage {
            ackno,
            window_size,
            rst: self.reassembler.output().has_error(),
        }
    }
}


#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn message(
        seqno: u32,
        syn: bool,
        payload: &'static [u8],
        fin: bool,
    ) -> TcpSenderMessage {
        TcpSenderMessage {
            seqno: Wrap32::new(seqno),
            syn,
            payload: Bytes::from_static(payload),
            fin,
            rst: false,
        }
    }

    #[test]
    fn receiver_has_no_ack_before_syn() {
        let receiver = TcpReceiver::new(10);

        let response = receiver.send();

        assert_eq!(response.ackno, None);
        assert_eq!(response.window_size, 10);
        assert!(!response.rst);
    }

    #[test]
    fn segment_without_syn_is_ignored_before_connection_starts() {
        let mut receiver = TcpReceiver::new(10);

        receiver
            .receive(message(1_001, false, b"abc", false))
            .unwrap();

        assert_eq!(receiver.output().bytes_pushed(), 0);
        assert_eq!(receiver.send().ackno, None);
    }

    #[test]
    fn syn_establishes_isn_and_advances_ack() {
        let mut receiver = TcpReceiver::new(10);

        receiver
            .receive(message(1_000, true, b"", false))
            .unwrap();

        assert_eq!(receiver.send().ackno, Some(Wrap32::new(1_001)));
        assert_eq!(receiver.send().window_size, 10);
    }

    #[test]
    fn syn_can_carry_payload() {
        let mut receiver = TcpReceiver::new(10);

        receiver
            .receive(message(1_000, true, b"abc", false))
            .unwrap();

        assert_eq!(receiver.output().peek(), b"abc");
        assert_eq!(receiver.send().ackno, Some(Wrap32::new(1_004)));
        assert_eq!(receiver.send().window_size, 7);
    }

    #[test]
    fn receiver_reassembles_out_of_order_payload() {
        let mut receiver = TcpReceiver::new(10);

        receiver
            .receive(message(1_000, true, b"", false))
            .unwrap();

        // Payload stream index 3 begins at absolute seqno 4,
        // which wraps to TCP seqno 1004.
        receiver
            .receive(message(1_004, false, b"def", false))
            .unwrap();

        assert_eq!(receiver.output().bytes_pushed(), 0);
        assert_eq!(receiver.reassembler().bytes_pending(), 3);
        assert_eq!(receiver.send().ackno, Some(Wrap32::new(1_001)));

        receiver
            .receive(message(1_001, false, b"abc", false))
            .unwrap();

        assert_eq!(receiver.output().peek(), b"abcdef");
        assert_eq!(receiver.reassembler().bytes_pending(), 0);
        assert_eq!(receiver.send().ackno, Some(Wrap32::new(1_007)));
    }

    #[test]
    fn fin_advances_ack_after_complete_reassembly() {
        let mut receiver = TcpReceiver::new(10);

        receiver
            .receive(message(1_000, true, b"abc", false))
            .unwrap();

        receiver
            .receive(message(1_004, false, b"de", true))
            .unwrap();

        assert_eq!(receiver.output().peek(), b"abcde");
        assert!(receiver.output().is_closed());

        // SYN + five payload bytes + FIN:
        //
        // absolute ACK = 1 + 5 + 1 = 7
        assert_eq!(receiver.send().ackno, Some(Wrap32::new(1_007)));
    }

    #[test]
    fn fin_waits_until_missing_prefix_arrives() {
        let mut receiver = TcpReceiver::new(10);

        receiver
            .receive(message(1_000, true, b"", false))
            .unwrap();

        receiver
            .receive(message(1_004, false, b"def", true))
            .unwrap();

        assert!(!receiver.output().is_closed());
        assert_eq!(receiver.send().ackno, Some(Wrap32::new(1_001)));

        receiver
            .receive(message(1_001, false, b"abc", false))
            .unwrap();

        assert!(receiver.output().is_closed());
        assert_eq!(receiver.output().peek(), b"abcdef");
        assert_eq!(receiver.send().ackno, Some(Wrap32::new(1_008)));
    }

    #[test]
    fn advertised_window_shrinks_and_reopens() {
        let mut receiver = TcpReceiver::new(5);

        receiver
            .receive(message(1_000, true, b"abc", false))
            .unwrap();

        assert_eq!(receiver.send().window_size, 2);

        receiver.output_mut().pop(2);

        assert_eq!(receiver.send().window_size, 4);
    }

    #[test]
    fn advertised_window_is_limited_to_u16_max() {
        let receiver = TcpReceiver::new(100_000);

        assert_eq!(receiver.send().window_size, u16::MAX);
    }

    #[test]
    fn rst_marks_stream_as_failed() {
        let mut receiver = TcpReceiver::new(10);

        receiver
            .receive(TcpSenderMessage {
                seqno: Wrap32::new(0),
                syn: false,
                payload: Bytes::new(),
                fin: false,
                rst: true,
            })
            .unwrap();

        assert!(receiver.output().has_error());
        assert!(receiver.send().rst);
    }

    #[test]
    fn receiver_handles_seqno_wraparound() {
        let isn = u32::MAX - 1;
        let mut receiver = TcpReceiver::new(10);

        receiver
            .receive(message(isn, true, b"cat", true))
            .unwrap();

        assert_eq!(receiver.output().peek(), b"cat");
        assert!(receiver.output().is_closed());

        // SYN  -> u32::MAX - 1
        // c    -> u32::MAX
        // a    -> 0
        // t    -> 1
        // FIN  -> 2
        // ACK  -> 3
        assert_eq!(receiver.send().ackno, Some(Wrap32::new(3)));
    }

    #[test]
    fn conflicting_retransmitted_syn_is_ignored() {
        let mut receiver = TcpReceiver::new(10);

        receiver
            .receive(message(1_000, true, b"", false))
            .unwrap();

        receiver
            .receive(message(2_000, true, b"abc", false))
            .unwrap();

        assert_eq!(receiver.output().bytes_pushed(), 0);
        assert_eq!(receiver.send().ackno, Some(Wrap32::new(1_001)));
    }
}