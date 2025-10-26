use std::io;

use libraries::benchmarking::*;


fn main() {
     loop {    println!("============================================================================");
                println!("Please enter a choice (1, 2, or 3) for the following routines, or 4 to exit:"); 
                println!("Please run in '--release' mode for accurate results.");
                println!("============================================================================");
                println!("(1)- Encryption/decryption corectness benchmarking with basic timing result.");
                println!("(2)- Full Runtime bench-marking of several implemented schemes.");
                println!("(3)- Performences benchmarking with respect to threshold value t.");
                println!("(4)- Binomial distrubution estimation for sensitivity benchmarking.");
                println!("(5)- Key sensitivity benchmarking");
                println!("(6)- `Parallelizme benchmarking ");
                println!("Enter 7 to leave ...");
                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let choice1: u32 = match input.trim().parse() {
                    Ok(num) => num,
                    Err(_) => {
                        println!("Invalid input. Please enter a number.");
                        return;
                    }
                };
                if choice1 == 7 {break;}
                match  choice1 { 1=> {   basic_bench();
                                     }
                                 2=> {  time_benchmark();
                                     }                              
                                 3=>{   threshold_bench();}
                                 4=>{   binomial_bench();  },
                                 5=> {  sensitivity_bench(TestParam::IV);
                                        sensitivity_bench(TestParam::KEY);
                                     }                        
                                 6=>{     parallel_bench();  },
                                 _ =>{}       
                                }
                }

}

