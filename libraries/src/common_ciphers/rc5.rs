use crate::common_ciphers::CipherInterface;
pub struct Rc5 {    core : rc5core::corerc::RC5128 }

impl Rc5 {
       pub const NAME: &'static str = "Rc5";
}

impl CipherInterface for Rc5 {
    type Cipher = Rc5;
    fn name(&self) -> &'static str {Rc5::NAME}

    fn level(&self) -> u16 {128}
    fn new(key :&[u128])->Self{
        Rc5{ core :rc5core::corerc::RC5128::new(key[0])}
    }

    fn encrypt_block(&self,input :u128) -> u128{
        self.core.encrypt_block(input)
    }

    fn decrypt_block(&self,input :u128) -> u128{
        self.core.decrypt_block(input)
    }
        
}