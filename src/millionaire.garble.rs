enum Richest {
    IsA,
    IsB,
    Tie,
}
pub fn main(a: u8, b: u8) -> Richest {
    if a > b {
        Richest::IsA
    } else if b > a {
        Richest::IsB
    } else {
        Richest::Tie
    }
}