use std::{arch::x86_64::*, ptr};
use smallvec::SmallVec;
use crate::{common_ciphers::{ CipherName, CommonCipher}, galois_arithmetic::{field::MAX_VECTOR_ELEMENTS, vector::GF128Vector, GF128Matrix}, GF128};

// Find optimal threshold with respect to the data size and the targted threshold 
pub fn fit_thresholds(blocks_count :usize,min_desired_threshold :usize)-> (usize,usize)
    {   
        if min_desired_threshold<2  {panic!("Minimal allowed value for the desired threshold  is 2")}
        if blocks_count<min_desired_threshold {(blocks_count,1)}
        else {  let a = blocks_count / (min_desired_threshold - 1);
                let b = blocks_count % (min_desired_threshold - 1);
                let mut result;
                if b==0 {    if min_desired_threshold <a {result = (min_desired_threshold,a-1)} 
                             else { result = (min_desired_threshold + (min_desired_threshold-1)/(a-1),a-1);
                                    if (min_desired_threshold-1) % (a-1) == 0 {result.0-=1}
                                }
                        }
                else  { if b <= a { result = (min_desired_threshold,a);}
                        else { result = (min_desired_threshold + b/a,a) ;
                                if b % a ==0 {result.0-=1}}                        
                        }
                result
            }        
    }

 pub fn generate_key_scheme(key :&[GF128],iv :&GF128, threshold :usize, prp :&CommonCipher) -> KeyScheme
{
        let _key;
        if key.len() ==1 {
            _key = key[0];
        }
        else {
            _key = prp.decrypt_block(key[0].to_u128()).into();
        }
        let iv_vec = GF128Vector::vec_from_iv(&_key, iv,threshold,prp);
        let vender_matrix = GF128Matrix::vandermonde(&iv_vec);
        let alpha = GF128Vector::alpha_from_iv(&_key, iv, threshold,prp);
        let beta = GF128Vector::beta_from_iv(&_key, iv, threshold,prp);
        let beta_vector = GF128Vector::beta_vector(&beta, 2*threshold-1);
        let mut inv_beta_vector = beta_vector.clone();
        for i in 0..inv_beta_vector.true_size {
                        inv_beta_vector.elements[i] = inv_beta_vector.elements[i].invert()
                    };
        let (principal_dec_matrice, secondary_dec_matrice) = vender_matrix.invert_vandermonde_both(threshold);
        let _key =if key.len() == 1 {[key[0],key[0]]} else {[key[0],key[1]]};
        KeyScheme { key  :_key,iv :*iv  , vender_matrix, principal_dec_matrice, secondary_dec_matrice, alpha, beta, beta_vector, inv_beta_vector }                    
            
        
} 

// Structure defining a decomposition level of the data to be encrypted/decrypted    
#[derive (Clone,Copy,Debug)]
pub struct LevelParams{
    pub start:usize,
    pub end:usize,
    pub blocks_count : usize,
    pub threshold: usize,
    pub max_part_size : usize,
    pub last_part_size:usize
}

pub struct KeyScheme {
    pub key : [GF128;2],
    pub iv :GF128,
    pub vender_matrix : GF128Matrix,
    pub principal_dec_matrice : GF128Matrix,
    pub secondary_dec_matrice :GF128Matrix,
    pub alpha :GF128,
    pub beta :GF128,
    pub beta_vector :GF128Vector,
    pub inv_beta_vector :GF128Vector
}

impl LevelParams {
    // Go down from a given decomposition level to the next according to the sharing threshold
    pub fn go_down(&mut self, min_threshold:usize){
                self.blocks_count = self.max_part_size;
                let new_part = fit_thresholds(self.blocks_count, min_threshold);               
                self.threshold = new_part.0;
                self.max_part_size = new_part.1;                    
                self.last_part_size = self.blocks_count % self.max_part_size; 
                self.end = self.max_part_size - 1;                    
            }
}

//  Definz a structur that enables representation of a given data bytes array as a Shamir's spliting structure 
//  that can be read as blocks, parts or vectors
pub struct SSCipherCore<'a> {
    pub targted_threshold : usize,
    pub internal: &'a mut Vec<GF128>, 
    tmp_vector : SmallVec<[__m128i; MAX_VECTOR_ELEMENTS]>,
    decryption_parts_stack : Vec<LevelParams>,
    pub active_level :LevelParams, 
    pub key_materials :KeyScheme, 
    pub prp_cipher: CommonCipher    
}

impl <'a> SSCipherCore<'a> {
    pub fn new(bytes: &[u8],in_length :usize, add_padd :bool, out_bytes :&'a mut Vec<GF128>, targted_threshold:usize,prp_name :CipherName) -> Self {                
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
                        if length % 16 == 0  {last_block = GF128::from(u128::from_le_bytes([16;16]))}                   
                        else {  // Implements padding scheme PCSK#1
                                let pad_size= 16 - length % 16;
                                let mut pad =[0u8;16];
                                for i in 0..16 {    if i>=16-pad_size {pad[i] = pad_size as u8}
                                                           else {pad[i] = bytes[(blocks_count-1)*16+i] as u8} 
                                                        }                                
                                last_block = GF128::from(u128::from_le_bytes(pad))
                                }
                        out_bytes[blocks_count-1] = last_block;
                    }
        let opt_params = fit_thresholds(blocks_count, targted_threshold);  // Get optimal thresholding parametres 
        let active_level = LevelParams{    start: 0, end: blocks_count-1,           // Get initial decomposition level parameters
                                                        blocks_count, threshold: opt_params.0, 
                                                        max_part_size :opt_params.1,
                                                        last_part_size : blocks_count % opt_params.1};
        let mut tmp_vector =SmallVec::<[__m128i; MAX_VECTOR_ELEMENTS]>::new();
        tmp_vector.resize(MAX_VECTOR_ELEMENTS, GF128::from(0).0);     
        let key1 = GF128::random();
        let key2 = GF128::random();                                                         
        let prp_cipher = CommonCipher::newcipher(&prp_name, &[key1.to_u128(),key2.to_u128()]);  
        let random_key_scheme = generate_key_scheme(&[key1,key2], &GF128::random(), targted_threshold,&prp_cipher);  
        SSCipherCore {  targted_threshold ,internal: out_bytes ,decryption_parts_stack :Vec::<LevelParams>::new(), 
                        active_level, tmp_vector ,key_materials :random_key_scheme, prp_cipher }
    }
    
    pub fn get_bytes_out(&self) -> &[u8] {
        unsafe {    std::slice::from_raw_parts(
                    self.internal.as_ptr() as *const u8,
                    self.internal.len() * 16
                    )
                }
    }

    pub fn get_block(&self, index: usize) -> GF128 {
        if index < self.internal.len() { self.internal[index]}            
        else {panic!("Index outside the size of data.")}
    }

    pub fn set_block(&mut self, index: usize, value :&GF128) {
        if index < self.internal.len() {self.internal[index] = *value} 
        else {panic!("Index outside the size of data.")}
    }

    // Define iterator on the structure blocks
    pub fn blocks(&self) -> impl Iterator<Item = GF128 > {        
        (0..self.active_level.blocks_count).filter_map(move |i| Some(self.get_block(i)))
    }

    pub fn set_key_scheme(&mut self,key :&[GF128],iv :&GF128){
        
        self.key_materials = generate_key_scheme(key, iv, self.targted_threshold, &self.prp_cipher);
    } 
    pub fn vectors_count(&self)-> usize{
        self.active_level.max_part_size
    }

    #[inline(always)]    
    pub fn encode_vector(&mut self, index: usize, alpha :&GF128, beta_vector :&GF128Vector) {
        let threshold = if index < self.active_level.last_part_size {self.active_level.threshold} 
                               else {self.active_level.threshold - 1};
        let alpha_val = *alpha;                               
        let internal_slice = &mut self.internal;
        let matrix_data = &self.key_materials.vender_matrix.data;
        let alpha_m128i = alpha_val.0;
        let tmp_values = &mut self.tmp_vector;    
        let bv = &beta_vector.elements;
        unsafe {    let mut j = 0;
                    for i in 0..threshold {  tmp_values[i] = ((internal_slice[j + index] + alpha_val).multiply(&bv[i])).0;
                                                    j += self.active_level.max_part_size;
                                                 }
                    for i in 0..threshold {
                        let mut acc_lo = _mm_setzero_si128();
                        let mut acc_hi = _mm_setzero_si128();                    
                        let matrix_row = &matrix_data[i];                    
                        for mj in 0..threshold {     let matrix_elem = matrix_row[mj].0;
                                                            let internal_elem = tmp_values[mj];                        
                                                            let h0 = _mm_clmulepi64_si128(matrix_elem, internal_elem, 0x00);
                                                            let h1 = _mm_clmulepi64_si128(matrix_elem, internal_elem, 0x01);
                                                            let h2 = _mm_clmulepi64_si128(matrix_elem, internal_elem, 0x10);
                                                            let h3 = _mm_clmulepi64_si128(matrix_elem, internal_elem, 0x11);                       
                                                            let h1h2 = _mm_xor_si128(h1, h2);
                                                            let prod_lo = _mm_xor_si128(h0, _mm_slli_si128(h1h2, 8));
                                                            let prod_hi = _mm_xor_si128(h3, _mm_srli_si128(h1h2, 8));                        
                                                            acc_lo = _mm_xor_si128(acc_lo, prod_lo);
                                                            acc_hi = _mm_xor_si128(acc_hi, prod_hi);
                                                        }                    
                        let poly = _mm_set_epi64x(0, 0x87);
                        let t0 = _mm_clmulepi64_si128(acc_hi, poly, 0x00);
                        let t1 = _mm_clmulepi64_si128(acc_hi, poly, 0x01);
                        let v0 = _mm_xor_si128(acc_lo, t0);
                        let v1 = _mm_xor_si128(v0, _mm_slli_si128(t1, 8));
                        let t2 = _mm_srli_si128(t1, 8);
                        let t3 = _mm_clmulepi64_si128(t2, poly, 0x00);
                        let result = GF128(_mm_xor_si128(v1, t3));
                        internal_slice[i * self.active_level.max_part_size + index] = GF128(_mm_xor_si128(result.0, alpha_m128i));
                    }
        }
    }

#[inline(always)]    
pub fn decode_vector(&mut self, index: usize, alpha :&GF128, inv_beta_vector :&GF128Vector) {
        let threshold = if index < self.active_level.last_part_size {self.active_level.threshold} 
                               else {self.active_level.threshold - 1};   
        let matrix = if index < self.active_level.last_part_size {&self.key_materials.principal_dec_matrice} else {&self.key_materials.secondary_dec_matrice};    
        let alpha_val = *alpha;
        let internal_slice = &mut self.internal;
        let matrix_data = &matrix.data;
        let alpha_m128i = alpha_val.0;
        let tmp_values = &mut self.tmp_vector;    
        unsafe {
            let mut j = 0;
            for i in 0..threshold {  tmp_values[i] = (internal_slice[j + index] + alpha_val).0;
                                            j += self.active_level.max_part_size;
                                        }        
            for i in 0..threshold {
                let mut acc_lo = _mm_setzero_si128();
                let mut acc_hi = _mm_setzero_si128();            
                let matrix_row = &matrix_data[i];            
                for mj in 0..threshold {     let matrix_elem = matrix_row[mj].0;
                                                    let internal_elem = tmp_values[mj];                
                                                    let h0 = _mm_clmulepi64_si128(matrix_elem, internal_elem, 0x00);
                                                    let h1 = _mm_clmulepi64_si128(matrix_elem, internal_elem, 0x01);
                                                    let h2 = _mm_clmulepi64_si128(matrix_elem, internal_elem, 0x10);
                                                    let h3 = _mm_clmulepi64_si128(matrix_elem, internal_elem, 0x11);                
                                                    let h1h2 = _mm_xor_si128(h1, h2);
                                                    let prod_lo = _mm_xor_si128(h0, _mm_slli_si128(h1h2, 8));
                                                    let prod_hi = _mm_xor_si128(h3, _mm_srli_si128(h1h2, 8));                
                                                    acc_lo = _mm_xor_si128(acc_lo, prod_lo);
                                                    acc_hi = _mm_xor_si128(acc_hi, prod_hi);
                                                }            
                let poly = _mm_set_epi64x(0, 0x87);
                let t0 = _mm_clmulepi64_si128(acc_hi, poly, 0x00);
                let t1 = _mm_clmulepi64_si128(acc_hi, poly, 0x01);
                let v0 = _mm_xor_si128(acc_lo, t0);
                let v1 = _mm_xor_si128(v0, _mm_slli_si128(t1, 8));
                let t2 = _mm_srli_si128(t1, 8);
                let t3 = _mm_clmulepi64_si128(t2, poly, 0x00);
                let result = GF128(_mm_xor_si128(v1, t3)).multiply(&inv_beta_vector.elements[i]);            
                internal_slice[i * self.active_level.max_part_size + index] = GF128(_mm_xor_si128(result.0, alpha_m128i));
            }
        }
    }

    pub fn encrypt(&mut self){        
        let save_part = self.active_level;
        while self.active_level.max_part_size > 1
                {  
                    let mut alpha = self.key_materials.alpha; 
                    let vectors_count = self.active_level.max_part_size;
                    let mut beta_vector = self.key_materials.beta_vector.clone();
                    for i in  0..vectors_count{
                                self.encode_vector(i, &alpha, &beta_vector);                                                                
                                alpha = alpha.multiply(&alpha);
                                for k in 0..self.active_level.threshold
                                                { beta_vector.elements[k] = beta_vector.elements[k].multiply(&beta_vector.elements[k])}
                                }                
                    self.active_level.go_down(self.targted_threshold);
                }
            let last_level_block = self.get_block(0);
            let encrypted_last_block = last_level_block.addto(&self.key_materials.iv).prp_encrypt (&self.prp_cipher);
            self.set_block(0, &encrypted_last_block);
            self.active_level = save_part;
    }

    
    pub fn decrypt(&mut self){
        fn get_levels(this : &mut SSCipherCore){
                if this.active_level.max_part_size > 1 {
                    this.decryption_parts_stack.push(this.active_level);
                    this.active_level.go_down(this.targted_threshold);
                    get_levels(this); 
                    }
            }        
        get_levels(self);
        let first_level_block = self.get_block(0);
        let decrypted_first_block = first_level_block.prp_decrypt(&self.prp_cipher).addto(&self.key_materials.iv);
        self.set_block(0, &decrypted_first_block); 
        while ! self.decryption_parts_stack.is_empty(){                
                self.active_level = self.decryption_parts_stack.pop().unwrap();
                let vectors_count = self.active_level.max_part_size;
                let mut alpha = self.key_materials.alpha.clone();
                let mut inv_beta_vector = self.key_materials.inv_beta_vector.clone();
                (self.key_materials.principal_dec_matrice,self.key_materials.secondary_dec_matrice) = 
                        self.key_materials.vender_matrix.invert_vandermonde_both(self.active_level.threshold);
                for i in 0..vectors_count 
                            {   self.decode_vector(i, &alpha, &inv_beta_vector);
                                alpha = alpha.multiply(&alpha);
                                for k in 0..self.active_level.threshold
                                                { inv_beta_vector.elements[k] = inv_beta_vector.elements[k].multiply(&inv_beta_vector.elements[k])}
                            }
            }
            // // Remove padding
            // if let Some(&pad_len) = self.internal.last() {   interface.out_bytes
            //                                                                 .resize(interface.out_bytes.len()
            //                                                                 .saturating_sub(pad_len as usize), 0);
            //                                                             }     
    }    
}

