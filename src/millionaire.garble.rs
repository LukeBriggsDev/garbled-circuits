pub fn main(a: u64, b: u64) -> u8 {
    if a > b {
        1u8
    } else if b > a {
        2u8
    } else {
        3u8
    }
}