use rand::Rng;
use std::time::Instant;
use common_ciphers::CipherName::*;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rayon::{iter::ParallelIterator, slice::ParallelSliceMut, ThreadPoolBuilder};
use std::time::Duration;

use crate::{cipher::{cbc_core::CBCCipherCore, core::SSCipherCore, ctr_core::CTRCipherCore}, common_ciphers::{self, CIPHER_128_NAMES, CIPHER_256_NAMES}, GF128};

pub enum TestParam { KEY,IV }

pub fn threshold_bench(){
    let mut data = Vec::<u8>::new();
    data.resize(160000, 1);
    let mut results_by_th:[f32;30]=[0.0;30];
    let mut count=0;
    let mut out = Vec::<GF128>::new();
    let key = GF128::random();
    let iv = GF128::random();
    let mut st: SSCipherCore<'_> ;
    for len in (10240..160000).step_by(1024){
    count+=1;
    for t in 4..30{
                st = SSCipherCore::new(&data,len, true, &mut out,t,AES128);
                st.set_key_scheme(&[key], &iv);
                let start: Instant = Instant::now();
                st.encrypt();
                let duration = start.elapsed();
                results_by_th[t]+=((len*1000000) as f32)/((duration.as_micros() as f32)*((1024*1024*1024) as f32));
                }
    }
    for t in 2..30{ results_by_th[t]/=count as f32;
    println!("t = {}: {:.3} GB/s",t,results_by_th[t]);
}}

pub fn time_benchmark(){
        let mut data = Vec::<u8>::new();    
        let max_size : usize =1073741824;
        let mut rng = rand::rng();
        data.resize_with(max_size, || rng.random::<u8>());
    for c in CIPHER_128_NAMES {
        let t_size :usize =10240;
        let mut out = Vec::<u128>::new();
        let mut st = CBCCipherCore::new(&data,t_size, true, &mut out,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for CBC with {}(128bit) 10KB (Lattence)=  {:?}",st.prp.name(), duration.as_micros());
        }
    for c in CIPHER_128_NAMES {
        let t_size :usize =10240;
        let mut out = Vec::<u128>::new();
        let mut st = CTRCipherCore::new(&data,t_size, true, &mut out,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for CTR with {}(128bit) 10KB (Lattence)=  {:?}",st.prp.name(), duration.as_micros());
        }
    for c in CIPHER_128_NAMES {
        let t_size :usize =10240;
        let mut out = Vec::<GF128>::new();
        let mut st = SSCipherCore::new(&data,t_size, true, &mut out,4,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for Proposed with {}(128bit) 10KB (Lattence)=  {:?}",st.prp_cipher.name(), duration.as_micros());
        }
    for c in CIPHER_128_NAMES {
        let t_size :usize =1073741824;
        let mut out = Vec::<u128>::new();
        let mut st = CBCCipherCore::new(&data,t_size, true, &mut out,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for CBC with {} 10KB (Throgput)=  {:?}",st.prp.name(), duration.as_secs());
        }
    for c in CIPHER_128_NAMES {
        let t_size :usize =1073741824;
        let mut out = Vec::<u128>::new();
        let mut st = CTRCipherCore::new(&data,t_size, true, &mut out,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for CTR with {} 10KB (Throgput)=  {:?}",st.prp.name(), duration.as_secs());
        }
    for c in CIPHER_128_NAMES {
        let t_size :usize =1073741824;
        let mut out = Vec::<GF128>::new();
        let mut st = SSCipherCore::new(&data,t_size, true, &mut out,4,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for Proposed with {} (Throgput)=  {:?}",st.prp_cipher.name(), duration.as_secs());
        }
    for c in CIPHER_256_NAMES {
        let t_size :usize =10240;
        let mut out = Vec::<u128>::new();
        let mut st = CBCCipherCore::new(&data,t_size, true, &mut out,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for CBC with {}(256bit) 10KB (Lattence)=  {:?}",st.prp.name(), duration.as_micros());
        }

    for c in CIPHER_256_NAMES {
        let t_size :usize =10240;
        let mut out = Vec::<u128>::new();
        let mut st = CTRCipherCore::new(&data,t_size, true, &mut out,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for CTR with {}(256bit) 10KB (Lattence)=  {:?}",st.prp.name(), duration.as_micros());
        }
    for c in CIPHER_256_NAMES {
        let t_size :usize =10240;
        let mut out = Vec::<GF128>::new();
        let mut st = SSCipherCore::new(&data,t_size, true, &mut out,4,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for Proposed with {}(256bit) 10KB (Lattence)=  {:?}",st.prp_cipher.name(), duration.as_micros());
        }
    for c in CIPHER_256_NAMES {
        let t_size :usize =1073741824;
        let mut out = Vec::<u128>::new();
        let mut st = CBCCipherCore::new(&data,t_size, true, &mut out,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for CBC with {} 10KB (Throgput)=  {:?}",st.prp.name(), duration.as_secs());
        }
    for c in CIPHER_256_NAMES {
        let t_size :usize =1073741824;
        let mut out = Vec::<u128>::new();
        let mut st = CTRCipherCore::new(&data,t_size, true, &mut out,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for CTR with {} 10KB (Throgput)=  {:?}",st.prp.name(), duration.as_secs());
        }
    for c in CIPHER_256_NAMES {
        let t_size :usize =1073741824;
        let mut out = Vec::<GF128>::new();
        let mut st = SSCipherCore::new(&data,t_size, true, &mut out,4,c);
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!(" Duration for Proposed with {} (Throgput)=  {:?}",st.prp_cipher.name(), duration.as_secs());
        }
}

pub fn sensitivity_bench( param :TestParam){
    fn bit_distances(t_size:usize,source: &[u8], dest: &[u8]) -> f32 {    
        let mut count: u128 = 0;
        for i in 0..t_size {
            count += (source[i] ^ dest[i]).count_ones() as u128;
        }
        count as f32 / (source.len() as f32 * 8.0)
    }
    let t_size :usize =10240;
    let mut data = Vec::<u8>::new();
    let mut rng = rand::rng();
    data.resize_with(t_size, || rng.random::<u8>());
    let mut out1 = Vec::<GF128>::new();
    let mut out2 = Vec::<GF128>::new();
    let key = GF128::random();
    let iv = GF128::random();
    let mut st = SSCipherCore::new(&data,t_size, true, &mut out1,4,AES128 );
    let mut st1 = SSCipherCore::new(&data,t_size, true, &mut out2,4,AES128 );
    let mut rng = rand::rng();
    for i in 0..128{
                let mut diff :f32 = 0.0;
                for _ in 0..1000{  
                            data.resize_with(t_size, || rng.random::<u8>());
                            st.set_key_scheme(&[key], &iv);
                            st.encrypt();
                            let res1 = st.get_bytes_out();
                            let iv1;
                            let key1;
                            match  param {
                                            TestParam::KEY => {   iv1 = iv ;
                                                                key1 = key ^ GF128::from(1<< i);},
                                            TestParam::IV => { iv1 = iv ^ GF128::from(1<< i);
                                                                key1 = key; },
                                        }

                            st1.set_key_scheme(&[key1], &iv1);
                            st1.encrypt();
                            let res2 = st1.get_bytes_out();        
                            diff = diff + bit_distances(t_size, res1, res2);
                        }
                println!("Diffrence percentage for bit {}: {} %",i+1,diff/(1000.0));
        }
}

pub fn binomial_bench(){
    fn bit_diffrence(t_size:usize,source: &[u8], dest: &[u8]) -> u128 {    
        let mut count: u128 = 0;
        for i in 0..t_size {
            count += (source[i] ^ dest[i]).count_ones() as u128;
        }
        count 
    }
    let mut data = Vec::<u8>::new();    
    let t_size = 1024;
    let mut rng = rand::rng();
    let iv = GF128::random();
    let mut out1 = Vec::<GF128>::new();
    let mut out2 = Vec::<GF128>::new();
    data.resize_with(t_size, || rng.random::<u8>());
    let mut st = SSCipherCore::new(&data,t_size, true, &mut out1,4,AES128 );
    let mut st1 = SSCipherCore::new(&data,t_size, true, &mut out2,4,AES128 );
    let mut v :[u128;8193]= [0;8193]; 
    for j in 0..10000{               
                        let key = GF128::random();           
                        for i in 0..128{
                                st.set_key_scheme(&[key], &iv);
                                st.encrypt();
                                let res1 = st.get_bytes_out();
                                let key1 = key ^ GF128::from(1<< i);
                                st1.set_key_scheme(&[key1], &iv);
                                st1.encrypt();
                                let res2 = st1.get_bytes_out();        
                                let k= bit_diffrence(t_size, res1, res2);                            
                                v[k as usize] =v [k as usize]+1;
                                }
                        println!("Iteration :{}",j);
                    }
        
    for i in 3804..4395{
        println!("{};{}",i,v[i] as f32/(128.0*10000.0))
    }
}

pub fn basic_bench(){
    let mut data = Vec::<u8>::new();
    let mut out = Vec::<GF128>::new();
    let targted_size : usize = 16000;
    data.resize(16000, 1);

    let mut st: SSCipherCore<'_> ;
    for c in CIPHER_128_NAMES {
        let level;
        match c {
            XTEA | Rc5| Cast| Aria| Serpent| AES128| Speck| Camellia| Lea => level = 128,
            Rc5256| Cast256| Aria256| AES256| XTEA256| Camellia256bit => level = 256,
        }
        let iv = GF128::random();
        if level ==128{
                        let key = GF128::random();
                        st = SSCipherCore::new(&data,targted_size, true, &mut out,4,c);
                        st.set_key_scheme(&[key], &iv);
                        }
        else {
                let key1 = GF128::random();
                let key2 = GF128::random();
                st = SSCipherCore::new(&data,targted_size, true, &mut out,4,c);
                st.set_key_scheme(&[key1,key2], &iv);
            }

        println!("{}", "-".repeat(100));
        println!("Benckmarking for the PRP '{}'",st.prp_cipher.name());
        // benchmark the proposed approach with the PRP
        let start: Instant = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!("Duration of the propsal = {:?}", duration);
        // Check Results of decryption correctness
        st.decrypt();
        let out = st.get_bytes_out();
        let mut check =true;
        for i in 0..targted_size{check &=out[i] == data[i]}
        println!("Check result correctness :{}",check);
        // benchmlark the CBC approach with the PRP
        let mut out = Vec::<u128>::new();
        let mut st = CBCCipherCore::new(&data,targted_size, true, &mut out,c);
        let start = Instant::now();
        st.encrypt();
        let duration = start.elapsed();
        println!("Duration with CBC  = {:?}",  duration);
    }
}

pub fn parallel_bench(){
    /// Simulated processing work for each chunk.
    /// We use u128 arithmetic to emulate moderate compute per 16 bytes.
    /// `compute_intensity` controls repeated ops to make workload more compute-heavy.
    fn process_chunk(chunk: &mut [u8], compute_intensity: usize) {
        // process 16 bytes at a time (u128)
        let mut i = 0usize;
        while i + 16 <= chunk.len() {
            // load 16 bytes -> u128 in little endian
            let mut val = u128::from_le_bytes(chunk[i..i + 16].try_into().unwrap());
            // apply simple non-linear mixing repeated compute_intensity times
            for _ in 0..compute_intensity {
                // some cheap but nontrivial ops: multiply + rotate + xor
                val = val.wrapping_mul(0x9E37_79B9_7F4A_7C15_9E37_79B97F4A7C15u128);
                val ^= val.rotate_left(13);
                val = val.wrapping_add(0x1234_5678_9ABC_DEF0_1234_56789ABCDEF0u128);
            }
            // write back
            chunk[i..i + 16].copy_from_slice(&val.to_le_bytes());
            i += 16;
        }
        // tail bytes: simple xor
        while i < chunk.len() {
            chunk[i] = chunk[i].wrapping_add(0xA5);
            i += 1;
        }
    }

    fn bench(data_size: usize,threads: usize,compute_intensity: usize,iterations: usize,) -> (Duration, f64) {
        // Setup thread pool for this run
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("build thread pool");
        // create RNG with fixed seed for reproducibility
        let mut rng = StdRng::seed_from_u64(0xDEADBEEFCAFEBABE);
        // allocate and fill data once (this cost is not measured)
        let mut data = vec![0u8; data_size];
        rng.fill_bytes(&mut data);
        // warmup run (not measured) to mitigate cold-start effects
        pool.install(|| {   let mut scratch = data.clone();
                                // perform one pass with low intensity
                                scratch
                                .chunks_mut(64 * 1024)
                                .for_each(|chunk| process_chunk(chunk, 1));
                        });
        // measured runs
        let start = Instant::now();
        for _ in 0..iterations {
            pool.install(|| {
                // clone input into local buffer per iteration (so each iteration is independent)
                let mut buf = data.clone();
                // pick chunk size: tune for cache locality.
                // Reasonable default: 64KB per task. We let rayon split automatically.
                buf.par_chunks_mut(64 * 1024).for_each(|chunk| {
                    process_chunk(chunk, compute_intensity);
                });
                // drop buf at end of closure
                std::hint::black_box(&buf);
            });
        }
        let dur = start.elapsed();
        // throughput in GB/s
        let total_bytes = (data_size as u128) * (iterations as u128);
        let seconds = dur.as_secs_f64();
        let gb_per_s = (total_bytes as f64) / (1024.0f64 * 1024.0 * 1024.0) / seconds;
        (dur, gb_per_s)
    }
    
    let sizes = [
        64 * 1024,         // 64 KB
        1 * 1024 * 1024,   // 1 MB
        100 * 1024 * 1024, // 100 MB
    ];
    // choose thread counts to test
    let thread_counts = [1usize, 2, 4, 8, 16];
    // control compute intensity: 0..light, larger -> heavier compute per byte
    let compute_intensity = 4usize; // tune this to move from memory- to compute-bound
    let iterations = 3usize; // repeat to avoid noisy tiny timings
    println!("Benchmark: iterations={} compute_intensity={}",iterations, compute_intensity);
    for &size in &sizes {   println!("--- Data size: {} bytes ---", size);
        for &t in &thread_counts {  // if threads > logical cores, still allowed but may not scale
                                            let (dur, gbps) = bench(size, t, compute_intensity, iterations);
                                            println!(
                                                "Size: {:>10} | Threads: {:>2} | Time: {:>8.4}s | Throughput: {:>6.3} GB/s",
                                                size,
                                                t,
                                                dur.as_secs_f64(),
                                                gbps
                                            );
                                        }
    }
}