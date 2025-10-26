use cipher::{ BlockDecrypt, BlockEncrypt, KeyInit};
#[allow(deprecated)]
use lea::prelude::GenericArray;

use crate::common_ciphers::CipherInterface;

pub struct Cast {    core :cast5::Cast5   }

impl Cast {
       pub const NAME: &'static str = "Cast";
}
impl CipherInterface for Cast {
    type Cipher = Cast;

    fn name(&self) -> &'static str {Cast::NAME}

    fn level(&self) -> u16 {128}

    fn new(key :&[u128])->Self{
        #[allow(deprecated)]
        let _key = GenericArray::from(key[0].to_be_bytes());
        let cipher: cast5::Cast5 = cast5::Cast5::new_from_slice(&_key).unwrap();
        Cast { core: cipher }
    }

    fn encrypt_block(&self,input :u128) -> u128{
        #[allow(deprecated)]
        let mut block1  = GenericArray::from((input as u64).to_be_bytes());
        #[allow(deprecated)]
        let mut block2  = GenericArray::from(((input >> 64) as u64).to_be_bytes());
        self.core.encrypt_block(&mut block1);
        self.core.encrypt_block(&mut block2);
        let a1 = u64::from_be_bytes(block1.into());
        let a2 = u64::from_be_bytes(block2.into());
        (a2 as u128) << 64 | (a1 as u128)
    }

    fn decrypt_block(&self,input :u128) -> u128{
        #[allow(deprecated)]
        let mut block1  = GenericArray::from((input as u64).to_be_bytes());
        #[allow(deprecated)]
        let mut block2  = GenericArray::from(((input >> 64) as u64).to_be_bytes());
        self.core.decrypt_block(&mut block1);
        self.core.decrypt_block(&mut block2);
        let a1 = u64::from_be_bytes(block1.into());
        let a2 = u64::from_be_bytes(block2.into());
        (a2 as u128) << 64 | (a1 as u128)
    }
        
}