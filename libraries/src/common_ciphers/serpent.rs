use cipher::{ BlockDecrypt, BlockEncrypt, KeyInit};
#[allow(deprecated)]
use lea::prelude::GenericArray;

use crate::common_ciphers::CipherInterface;

pub struct Serpent128 {    core :serpent::Serpent   }

impl Serpent128 {
       pub const NAME: &'static str = "SERPENT";
}
impl CipherInterface for Serpent128 {
    type Cipher = Serpent128;

    fn name(&self) -> &'static str {Serpent128::NAME}

    fn level(&self) -> u16 {128}

    fn new(key :&[u128])->Self{
        #[allow(deprecated)]
        let _key = GenericArray::from(key[0].to_be_bytes());
        let cipher = serpent::Serpent::new(&_key);
        Serpent128 { core: cipher }
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