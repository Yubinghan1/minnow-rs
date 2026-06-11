const MODULUS: u64=1_u64 << 32;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Wrap32(u32);

impl Wrap32{
    pub const fn new(raw_value:u32)->Self{
        Self(raw_value)
    }

    pub const fn raw_value(self)->u32{
        self.0
    }

    pub fn wrap(absolute_seqno:u64,zero_point:Self)->Self{
        Self(zero_point.0.wrapping_add(absolute_seqno as u32))
    }

    pub fn unwrap(self,zero_point:Self,checkpoint:u64)->u64{
        let offset=self.0.wrapping_sub(zero_point.0) as u64;

        let era_start=checkpoint/MODULUS*MODULUS;

        let current=era_start+offset;
        
        let mut best=current;
        let mut best_distance=current.abs_diff(checkpoint);

        if let Some(previous)=current.checked_sub(MODULUS){
            let distance=previous.abs_diff(checkpoint);

            if distance<best_distance{
                best=previous;
                best_distance=distance;
            }
        }
        
        if let Some(next)=current.checked_add(MODULUS){
            let distance=next.abs_diff(checkpoint);

            if distance<best_distance{
                best=next;
                best_distance=distance;
            }
        }

        best
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_value_round_trip() {
        let value = Wrap32::new(123);

        assert_eq!(value.raw_value(), 123);
    }

    #[test]
    fn wrap_without_overflow() {
        let isn = Wrap32::new(1_000);

        assert_eq!(Wrap32::wrap(0, isn), Wrap32::new(1_000));
        assert_eq!(Wrap32::wrap(5, isn), Wrap32::new(1_005));
    }

    #[test]
    fn wrap_crosses_u32_boundary() {
        let isn = Wrap32::new(u32::MAX - 1);

        assert_eq!(Wrap32::wrap(0, isn), Wrap32::new(u32::MAX - 1));
        assert_eq!(Wrap32::wrap(1, isn), Wrap32::new(u32::MAX));
        assert_eq!(Wrap32::wrap(2, isn), Wrap32::new(0));
        assert_eq!(Wrap32::wrap(3, isn), Wrap32::new(1));
    }

    #[test]
    fn unwrap_without_wraparound() {
        let isn = Wrap32::new(1_000);
        let seqno = Wrap32::new(1_005);

        assert_eq!(seqno.unwrap(isn, 4), 5);
    }

    #[test]
    fn unwrap_selects_first_era_near_small_checkpoint() {
        let isn = Wrap32::new(0);
        let seqno = Wrap32::new(17);

        assert_eq!(seqno.unwrap(isn, 20), 17);
    }

    #[test]
    fn unwrap_selects_later_era_near_large_checkpoint() {
        let isn = Wrap32::new(0);
        let seqno = Wrap32::new(17);

        assert_eq!(seqno.unwrap(isn, MODULUS + 20), MODULUS + 17);
    }

    #[test]
    fn unwrap_handles_wrapped_isn() {
        let isn = Wrap32::new(u32::MAX - 1);

        assert_eq!(Wrap32::new(0).unwrap(isn, 2), 2);
        assert_eq!(Wrap32::new(1).unwrap(isn, 3), 3);
    }

    #[test]
    fn wrap_and_unwrap_round_trip_across_multiple_eras() {
        let isn = Wrap32::new(9_876);
        let absolute = 3 * MODULUS + 123;

        let wrapped = Wrap32::wrap(absolute, isn);

        assert_eq!(wrapped.unwrap(isn, absolute), absolute);
    }
}