// Camellia-128 Block Cipher Implementation
// Based on RFC 3713 specification

use camellia::Camellia256;
#[allow(deprecated)]
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

use super::CipherInterface;

pub struct Camellia256bit {
    core :Camellia256
}
impl Camellia256bit{
       pub const NAME: &'static str = "CAMELLIA256";
}
impl CipherInterface for  Camellia256bit{
    type Cipher = Camellia256bit;

    fn name(&self) -> &'static str {Camellia256bit::NAME}
    fn level(&self) -> u16 {256}
    
    fn new(key :&[u128])->Self
    {
        fn u128_slice_to_u8_slice_unsafe(input: &[u128]) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                input.as_ptr() as *const u8,
                input.len() * std::mem::size_of::<u128>()
                )
                }
        }
        let _key =u128_slice_to_u8_slice_unsafe(key);
        let cipher = Camellia256::new_from_slice(&_key).expect("Invalid key");
        Camellia256bit { core: cipher }
    }

    fn encrypt_block(&self,input :u128) -> u128{
        #[allow(deprecated)]
        let mut block = GenericArray::from(input.to_be_bytes());
        self.core.encrypt_block(&mut block);
        u128::from_be_bytes(block.into())
    }

    fn decrypt_block(&self,input :u128) -> u128{
        #[allow(deprecated)]
        let mut block = GenericArray::from(input.to_be_bytes());
        self.core.decrypt_block(&mut block);
        u128::from_be_bytes(block.into())
    }
    
    
}

