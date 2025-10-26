use super::CipherInterface;

pub struct Speck {    core :speck::Key}

impl Speck{
       pub const NAME: &'static str = "SPECK";
}

impl CipherInterface for  Speck{
    type Cipher = Speck;
    fn name(&self) -> &'static str {Speck::NAME}

    fn level(&self) -> u16 {128}
    
    fn new(key :&[u128])->Self{
        let cipher = speck::Key::new(key[0]);
        Speck  { core: cipher }
    }

    fn encrypt_block(&self,input :u128) -> u128{
        self.core.encrypt_block(input)
    }

    fn decrypt_block(&self,input :u128) -> u128{
        self.core.decrypt_block(input)
    }
}

