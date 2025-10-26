use std::time::Instant;

use aes::AES128;
use camellia::Camellia;
use lea::Lea;
use rand::Rng;
use speck::Speck;
use xtea::XTEA;

use crate::common_ciphers::{aes256::AES256, aria::Aria, aria256::Aria256, camelia256::Camellia256bit, cast::Cast, cast256::Cast256, rc5::Rc5, rc5256::Rc5256, serpent::Serpent128, xtea256::XTEA256};

pub trait CipherInterface{
    type Cipher;
    fn new(key: &[u128]) -> Self::Cipher;
    fn encrypt_block(&self, input: u128) -> u128;
    fn decrypt_block(&self, input: u128) -> u128;
    fn name(&self) -> &'static str;
    fn level(&self) -> u16;
}

pub mod aes;
pub mod xtea;
pub mod camellia;
pub mod speck;
pub mod lea;
pub mod serpent;
pub mod aria;
pub mod aria256;
pub mod cast;
pub mod cast256;
pub mod rc5;
pub mod rc5256;
pub mod aes256;
pub mod camelia256;
pub mod xtea256;

#[derive(Copy, Clone, Debug)]
pub enum CipherName {
    XTEA,
    XTEA256,
    Speck,
    Lea,
    Camellia,
    Camellia256bit,
    AES128,  
    AES256,  
    Serpent,
    Aria,
    Aria256,
    Cast,
    Cast256,
    Rc5,
    Rc5256
}

pub enum CommonCipher {
    XTEA(XTEA),
    XTEA256(XTEA256),
    Speck(Speck),
    Lea(Lea),
    Camellia(Camellia),
    Camellia256bit(Camellia256bit),
    AES128(AES128),
    AES256(AES256),
    Serpent128(Serpent128),
    Aria(Aria),
    Aria256(Aria256),
    Cast(Cast),
    Cast256(Cast256),
    Rc5(Rc5),
    Rc5256(Rc5256)
}

impl CommonCipher {
    pub fn newcipher(name: &CipherName, key: &[u128]) -> Self {
        match name {
            CipherName::XTEA => Self::XTEA(XTEA::new(key)),
            CipherName::XTEA256 => Self::XTEA256(XTEA256::new(key)),
            CipherName::Speck => Self::Speck(Speck::new(key)),
            CipherName::Lea => Self::Lea(Lea::new(key)),
            CipherName::Camellia => Self::Camellia(Camellia::new(key)),
            CipherName::Camellia256bit => Self::Camellia256bit(Camellia256bit::new(key)),
            CipherName::AES128 => Self::AES128(AES128::new(key)),
            CipherName::AES256 => Self::AES256(AES256::new(key)),
            CipherName::Serpent => Self::Serpent128(Serpent128::new(key)),
            CipherName::Aria => Self::Aria(Aria::new(key)),
            CipherName::Aria256 => Self::Aria256(Aria256::new(key)),
            CipherName::Cast => Self::Cast(Cast::new(key)),
            CipherName::Cast256 => Self::Cast256(Cast256::new(key)),
            CipherName::Rc5 => Self::Rc5(Rc5::new(key)),
            CipherName::Rc5256 => Self::Rc5256(Rc5256::new(key))

        }
    }

    pub fn level(&self)-> u16{
        match self {
            Self::XTEA(c) => c.level(),
            Self::XTEA256(c) => c.level(),
            Self::Speck(c) => c.level(),
            Self::Lea(c) => c.level(),
            Self::Camellia(c) => c.level(),
            Self::Camellia256bit(c) => c.level(),
            Self::AES128(c) => c.level(),
            Self::AES256(c) => c.level(),
            Self::Serpent128(c) =>c.level(),
            Self::Aria(c) =>c.level(),
            Self::Aria256(c) =>c.level(),
            Self::Cast(c) =>c.level(),
            Self::Cast256(c) =>c.level(),
            Self::Rc5(c) =>c.level(),
            Self::Rc5256(c) =>c.level()
        }

    }

    pub fn encrypt_block(&self, input: u128) -> u128 {
        match self {
            Self::XTEA(c) => c.encrypt_block(input),
            Self::XTEA256(c) => c.encrypt_block(input),
            Self::Speck(c) => c.encrypt_block(input),
            Self::Lea(c) => c.encrypt_block(input),
            Self::Camellia(c) => c.encrypt_block(input),
            Self::Camellia256bit(c) => c.encrypt_block(input),
            Self::AES128(c) => c.encrypt_block(input),
            Self::AES256(c) => c.encrypt_block(input),
            Self::Serpent128(c) =>c.encrypt_block(input),
            Self::Aria(c) =>c.encrypt_block(input),
            Self::Aria256(c) =>c.encrypt_block(input),
            Self::Cast(c) =>c.encrypt_block(input),
            Self::Cast256(c) =>c.encrypt_block(input),
            Self::Rc5(c) =>c.encrypt_block(input),
            Self::Rc5256(c) =>c.encrypt_block(input)
        }
    }

    pub fn decrypt_block(&self, input: u128) -> u128 {
        match self {
            Self::XTEA(c) => c.decrypt_block(input),
            Self::XTEA256(c) => c.decrypt_block(input),
            Self::Speck(c) => c.decrypt_block(input),
            Self::Lea(c) => c.decrypt_block(input),
            Self::Camellia(c) => c.decrypt_block(input),
            Self::Camellia256bit(c) => c.decrypt_block(input),
            Self::AES128(c) => c.decrypt_block(input),
            Self::AES256(c) => c.decrypt_block(input),
            Self::Serpent128(c)=>c.decrypt_block(input),
            Self::Aria(c)=>c.decrypt_block(input),
            Self::Aria256(c)=>c.decrypt_block(input),
            Self::Cast(c)=>c.decrypt_block(input),
            Self::Cast256(c)=>c.decrypt_block(input),
            Self::Rc5(c)=>c.decrypt_block(input),
            Self::Rc5256(c)=>c.decrypt_block(input)
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::XTEA(_) => "XTEA",
            Self::XTEA256(_) => "XTEA256",
            Self::Speck(_) => "Speck",
            Self::Lea(_) => "Lea",
            Self::Camellia(_) => "Camellia",
            Self::Camellia256bit(_) => "Camellia256",
            Self::AES128(_) => "AES128",
            Self::AES256(_) => "AES256",
            Self::Serpent128(_)=>"Serpent",
            Self::Aria(_)=>"Aria",
            Self::Aria256(_)=>"Aria256",
            Self::Cast(_)=>"Cast",
            Self::Cast256(_)=>"Cast256",
            Self::Rc5(_)=>"Rc5",
            Self::Rc5256(_)=>"Rc5256"
        }
    }
}

pub const CIPHER_NAMES: [CipherName; 14] = [
        CipherName::XTEA,
        CipherName::XTEA256,
        CipherName::Speck,
        CipherName::Lea,
        CipherName::Camellia,
        CipherName::Camellia256bit,
        CipherName::AES128,
        CipherName::AES256,
        //CipherName::Serpent,
        CipherName::Aria,
        CipherName::Aria256,
        CipherName::Cast,
        CipherName::Cast256,
        CipherName::Rc5,
        CipherName::Rc5256
    ];

pub const CIPHER_128_NAMES: [CipherName; 6] = [
        CipherName::XTEA,
        CipherName::Camellia,
        CipherName::AES128,
        CipherName::Aria,
        CipherName::Cast,
        CipherName::Rc5,
    ];

pub const CIPHER_256_NAMES: [CipherName; 6] = [
        CipherName::XTEA256,
        CipherName::Camellia256bit,
        CipherName::AES256,
        CipherName::Aria256,
        CipherName::Cast256,
        CipherName::Rc5256
    ];
pub fn bench_ciphers() {
    const NUM_TRYS: usize = 1_000_000;
    let key1 = rand::rng().random::<u128>();
    let key2 = rand::rng().random::<u128>();
    let ciphers: Vec<CommonCipher> = CIPHER_NAMES
        .iter()
        .filter_map(|cipher| Some(CommonCipher::newcipher(cipher, &[key1,key2])))
        .collect();

    let mut plain = rand::rng().random::<u128>();
    
    for c in ciphers {
        let start = Instant::now();
        for _ in 0..NUM_TRYS {
            plain = c.encrypt_block(plain);
        }
        let duration = start.elapsed();
        println!("Duration for {} = {:?}", c.name(), duration);
    }
}