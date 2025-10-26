// Camellia-128 Block Cipher Implementation
// Based on RFC 3713 specification

use camellia::Camellia128;
#[allow(deprecated)]
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

use super::CipherInterface;

pub struct Camellia {
    core :Camellia128
}
impl Camellia{
       pub const NAME: &'static str = "CAMELLIA";
}
impl CipherInterface for  Camellia{
    type Cipher = Camellia;

    fn name(&self) -> &'static str {Camellia::NAME}

    fn level(&self) -> u16 {128}
    
    fn new(key :&[u128])->Self
    {
        let cipher = Camellia128::new_from_slice(&key[0].to_be_bytes()).expect("Invalid key");
        Camellia { core: cipher }
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

