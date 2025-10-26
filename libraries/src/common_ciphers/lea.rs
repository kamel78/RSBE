// Lea-128 Block Cipher Implementation
use lea::{prelude::*, Lea128};

use super::CipherInterface;

pub struct Lea {    core :Lea128   }

impl Lea{
       pub const NAME: &'static str = "LEA";
}
impl CipherInterface for Lea {
    type Cipher = Lea;

    fn name(&self) -> &'static str {Lea::NAME}

    fn level(&self) -> u16 {128}

    fn new(key :&[u128])->Self{
        #[allow(deprecated)]
        let _key = GenericArray::from(key[0].to_be_bytes());
        let cipher = Lea128::new(&_key);
        Lea { core: cipher }
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

