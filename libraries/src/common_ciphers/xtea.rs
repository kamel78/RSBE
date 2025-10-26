use super::CipherInterface;

pub struct XTEA {
    key: [u32; 4],
}

impl XTEA {
   pub const NAME: &'static str = "XTEA";
    #[inline]
    fn encrypt_block_tow_parts(&self, mut v0: u32, mut v1: u32) -> (u32, u32) {
        const DELTA: u32 = 0x9E3779B9;
        let mut sum = 0u32;

        for _ in 0..32 {    let temp = ((v1 << 4) ^ (v1 >> 5))
                                            .wrapping_add(v1)
                                            .wrapping_add(sum)
                                            .wrapping_add(self.key[(sum & 3) as usize]);
                            v0 = v0.wrapping_add(temp);
                            sum = sum.wrapping_add(DELTA);                            
                            let temp = ((v0 << 4) ^ (v0 >> 5))
                                            .wrapping_add(v0)
                                            .wrapping_add(sum)
                                            .wrapping_add(self.key[((sum >> 11) & 3) as usize]);
                            v1 = v1.wrapping_add(temp);
                        }        
        (v0, v1)
    }

    #[inline]
    fn decrypt_block_tow_parts(&self, mut v0: u32, mut v1: u32) -> (u32, u32) {
        const DELTA: u32 = 0x9E3779B9;
        let mut sum = DELTA << 5; // DELTA * 32
        for _ in 0..32 {    let temp = ((v0 << 4) ^ (v0 >> 5))
                                            .wrapping_add(v0)
                                            .wrapping_add(sum)
                                            .wrapping_add(self.key[((sum >> 11) & 3) as usize]);
                            v1 = v1.wrapping_sub(temp);
                            sum = sum.wrapping_sub(DELTA);                            
                            let temp = ((v1 << 4) ^ (v1 >> 5))
                                            .wrapping_add(v1)
                                            .wrapping_add(sum)
                                            .wrapping_add(self.key[(sum & 3) as usize]);
                            v0 = v0.wrapping_sub(temp);
                        }
                        (v0, v1)
        }

    #[inline]
    fn u64_to_blocks(value: u64) -> (u32, u32) {
        ((value >> 32) as u32, value as u32)
    }

    #[inline]
    fn blocks_to_u64(high: u32, low: u32) -> u64 {
        ((high as u64) << 32) | (low as u64)
    }
}

impl  CipherInterface for XTEA {
     
    type Cipher = XTEA;
    fn name(&self) -> &'static str {XTEA::NAME}

    fn level(&self) -> u16 {128}
    
    fn new(key: &[u128]) -> Self {
        let k = [   (key[0] >> 96) as u32, (key[0] >> 64) as u32,  (key[0] >> 32) as u32,   key[0] as u32];
        XTEA { key: k }
    }
    fn encrypt_block(&self, input: u128) -> u128 {
        let left = (input >> 64) as u64;
        let right = input as u64;
        let (l_high, l_low) = Self::u64_to_blocks(left);
        let (r_high, r_low) = Self::u64_to_blocks(right);
        let (l0, l1) = self.encrypt_block_tow_parts(l_high, l_low);
        let (r0, r1) = self.encrypt_block_tow_parts(r_high, r_low);
        let left_enc = Self::blocks_to_u64(l0, l1);
        let right_enc = Self::blocks_to_u64(r0, r1);
        ((left_enc as u128) << 64) | (right_enc as u128)
    }
    
    fn decrypt_block(&self, input: u128) -> u128 {
        let left = (input >> 64) as u64;
        let right = input as u64;
        let (l_high, l_low) = Self::u64_to_blocks(left);
        let (r_high, r_low) = Self::u64_to_blocks(right);
        let (l0, l1) = self.decrypt_block_tow_parts(l_high, l_low);
        let (r0, r1) = self.decrypt_block_tow_parts(r_high, r_low);
        let left_dec = Self::blocks_to_u64(l0, l1);
        let right_dec = Self::blocks_to_u64(r0, r1);
        ((left_dec as u128) << 64) | (right_dec as u128)
    }
      
    
}