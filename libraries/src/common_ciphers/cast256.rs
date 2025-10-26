use cipher::{ BlockDecrypt, BlockEncrypt, KeyInit};
#[allow(deprecated)]
use lea::prelude::GenericArray;

use crate::common_ciphers::CipherInterface;

pub struct Cast256 {    core :cast6::Cast6   }

impl Cast256 {
       pub const NAME: &'static str = "Cast256";
}
impl CipherInterface for Cast256 {
    type Cipher = Cast256;

    fn name(&self) -> &'static str {Cast256::NAME}

    fn level(&self) -> u16 {256}

    fn new(key :&[u128])->Self{
        fn u128_slice_to_u8_slice_unsafe(input: &[u128]) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                input.as_ptr() as *const u8,
                input.len() * std::mem::size_of::<u128>()
                )
                }
        }
        let _key =u128_slice_to_u8_slice_unsafe(key);
        let cipher = cast6::Cast6::new_from_slice(&_key).unwrap();
        Cast256 { core: cipher }
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