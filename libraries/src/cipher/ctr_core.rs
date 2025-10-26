use std::ptr;
use rand::Rng;
use crate::common_ciphers::{CipherName,  CommonCipher};

pub struct CTRCipherCore <'a>{
    pub internal: &'a mut Vec<u128>,
    pub blocks_count :usize,
    pub prp_name :CipherName,
    pub prp :CommonCipher, 
    iv :u128,
    key :[u128;2]
    }

impl <'a>CTRCipherCore<'a>{    
    pub fn new(bytes: &[u8], in_length :usize,add_padd :bool, out_bytes :&'a mut Vec<u128>, prp_name :CipherName) -> Self {                
        let length = if in_length==0 {bytes.len()} else {in_length};
        let blocks_count = (length / 16) + if add_padd {1} else {0};
        out_bytes.reserve(blocks_count);
        unsafe {       ptr::copy_nonoverlapping(
                                bytes.as_ptr(),
                                out_bytes.as_mut_ptr() as *mut u8,
                                length - (length %16)
                                );
                        out_bytes.set_len(blocks_count);
                }                 
        if add_padd {   let last_block;     
                        if length % 16 == 0  {last_block = u128::from_le_bytes([16;16])}                   
                        else {  // Implements padding scheme PCSK#1
                                let pad_size= 16 - length % 16;
                                let mut pad =[0u8;16];
                                for i in 0..16 {    if i>=16-pad_size {pad[i] = pad_size as u8}
                                                           else {pad[i] = bytes[(blocks_count-1)*16+i] as u8} 
                                                        }                                
                                last_block = u128::from_le_bytes(pad)
                                }
                        out_bytes[blocks_count-1] = last_block;
                    }
        let key1 = rand::rng().random::<u128>();
        let key2 = rand::rng().random::<u128>();
        let iv = rand::rng().random::<u128>();
        let prp = CommonCipher::newcipher(&prp_name,&[key1,key2]);        
        CTRCipherCore {  internal: out_bytes, blocks_count, prp , prp_name, iv, key: [key1,key2] }
    }
    
    pub fn get_bytes_out(&self) -> &[u8] {
        unsafe {    std::slice::from_raw_parts(
                    self.internal.as_ptr() as *const u8,
                    self.internal.len() * 16
                    )
                }
    }

    pub fn set_key_materials(&mut self, key :&[u128], iv:u128, prp_name :CipherName){
        self.prp = CommonCipher::newcipher(&prp_name, key);
        self.key = [key[0],key[1]];
        self.iv =iv;
        self.prp_name =prp_name;
    }

    pub fn get_block(&self, index: usize) -> u128 {
        if index < self.internal.len() { self.internal[index]}            
        else {panic!("Index outside the size of data.")}
    }

    pub fn set_block(&mut self, index: usize, value :u128) {
        if index < self.internal.len() {self.internal[index] = value} 
        else {panic!("Index outside the size of data.")}
    }
    
    pub fn blocks(&self) -> impl Iterator<Item = u128 > {        
        (0..self.blocks_count).filter_map(move |i| Some(self.get_block(i)))
    }

           
    pub fn encrypt(&mut self) {
            // let previous_block = self.iv;
            for i in 0..self.blocks_count{
                    // let encrypted_block = self.prp.encrypt_block(self.get_block(i) ^ previous_block);
                    let encrypted_block = self.prp.encrypt_block(self.iv + i as u128) ^ self.get_block(i);
                    self.set_block(i, encrypted_block);
                }            
    }

   pub fn decrypt(&mut self) {
            // let previous_block = self.iv;
            for i in 0..self.blocks_count{
                    // let decrypted_block = self.prp.decrypt_block(self.get_block(i))^ previous_block;
                    let decrypted_block = self.prp.encrypt_block(self.iv + i as u128) ^ self.get_block(i);
                    self.set_block(i, decrypted_block);
                }            
    }
}