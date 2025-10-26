use crate::common_ciphers::CipherInterface;
pub struct Rc5256 {    core : rc5core::corerc::RC5256 }

impl Rc5256 {
       pub const NAME: &'static str = "Rc5256";
}

impl CipherInterface for Rc5256 {
    type Cipher = Rc5256;
    fn name(&self) -> &'static str {Rc5256::NAME}

    fn level(&self) -> u16 {256}

    fn new(key :&[u128])->Self{
        Rc5256{ core :rc5core::corerc::RC5256::new(key[0],key[1])}
    }

    fn encrypt_block(&self,input :u128) -> u128{
        self.core.encrypt_block(input)
    }

    fn decrypt_block(&self,input :u128) -> u128{
        self.core.decrypt_block(input)
    }
        
}