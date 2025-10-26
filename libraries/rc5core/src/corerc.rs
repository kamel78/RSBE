use cipher::{consts::{ U16, U32, U58, U68}, Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use crate::RC5;

pub struct RC5128 {  cipher:RC5<u64, cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UTerm, cipher::consts::B1>, cipher::consts::B1>, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B1>, cipher::consts::B0>, cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UTerm, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>> }

impl RC5128 {
    pub fn new(key :u128)->Self{
        let cipher:RC5<u64, cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UTerm, cipher::consts::B1>, cipher::consts::B1>, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B1>, cipher::consts::B0>, cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UTerm, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>>= <RC5<u64, U58, U16> as KeyInit>::new_from_slice(&key.to_be_bytes()).unwrap();        
        RC5128 { cipher }
    }

    pub fn encrypt_block(&self,input :u128) -> u128{
     
        let mut block = Array::try_from(input.to_be_bytes()).unwrap();
        self.cipher.encrypt_block(&mut block);
        u128::from_be_bytes(block.into())
    }

    pub fn decrypt_block(&self,input :u128) -> u128{
        let mut block = Array::try_from(input.to_be_bytes()).unwrap();
        self.cipher.decrypt_block(&mut block);
        u128::from_be_bytes(block.into())
    }
        
}

pub struct RC5256 {  cipher:RC5<u64, cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UTerm, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B0>, cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UTerm, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>>}

impl RC5256 {
    pub fn new(key1 :u128,key2:u128)->Self{
        fn u128_slice_to_u8_slice_unsafe(input: &[u128]) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                input.as_ptr() as *const u8,
                input.len() * std::mem::size_of::<u128>()
                )
                }
        }
        let binding = [key1,key2];
        let _key =u128_slice_to_u8_slice_unsafe(&binding);
        let cipher: RC5<u64, cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UTerm, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B0>, cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UInt<cipher::typenum::UTerm, cipher::consts::B1>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>, cipher::consts::B0>>= <RC5<u64, U68, U32> as KeyInit>::new_from_slice(&_key).unwrap();        
        RC5256 { cipher }
    }

    pub fn encrypt_block(&self,input :u128) -> u128{
     
        let mut block = Array::try_from(input.to_be_bytes()).unwrap();
        self.cipher.encrypt_block(&mut block);
        u128::from_be_bytes(block.into())
    }

    pub fn decrypt_block(&self,input :u128) -> u128{
        let mut block = Array::try_from(input.to_be_bytes()).unwrap();
        self.cipher.decrypt_block(&mut block);
        u128::from_be_bytes(block.into())
    }
        
}

