
use rekkoex::ekko;

#[allow(non_snake_case, unused_variables)]
fn main() {
    println!("[*] Ekko Sleep Obfuscation by @memN0ps and @trickster0. Full credits to Cracked5pider (@C5pider), Austin Hudson (@SecIdiot), Peter Winter-Smith (@peterwintrsmith)");
    
    let mut key_buf = "1234567890ABCDEF\0".as_bytes().to_vec();
    loop {
        ekko(2000, &mut key_buf);
        println!("Sleeping for 2 seconds...");
        //std::thread::sleep(std::time::Duration::from_secs(2));
    }

}