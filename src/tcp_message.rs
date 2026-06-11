use bytes::Bytes;

use crate::wrapping_integers::Wrap32;

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct TcpSenderMessage{
    pub seqno: Wrap32,
    pub syn:bool,
    pub payload:Bytes,
    pub fin:bool,
    pub rst:bool,
}

impl TcpSenderMessage{
    pub fn new(seqno:Wrap32)->Self{
        Self { seqno, syn: false, payload: Bytes::new(), fin: false, rst:false }
    }

    pub fn sequence_length(&self)->usize{
        usize::from(self.syn)+self.payload.len()+usize::from(self.fin)
    }

}

#[derive(Debug,Clone,Copy,Default,PartialEq,Eq)]
pub struct TcpReceiverMessage{
    pub ackno:Option<Wrap32>,
    pub window_size:u16,
    pub rst:bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_message_sequence_length_counts_syn_payload_and_fin() {
        let message = TcpSenderMessage {
            seqno: Wrap32::new(100),
            syn: true,
            payload: Bytes::from_static(b"cat"),
            fin: true,
            rst: false,
        };

        assert_eq!(message.sequence_length(), 5);
    }

    #[test]
    fn empty_message_occupies_no_sequence_numbers() {
        let message = TcpSenderMessage::new(Wrap32::new(100));

        assert_eq!(message.sequence_length(), 0);
    }
}