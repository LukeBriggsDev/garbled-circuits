pub fn main(a: i64, b: i64) -> i64 {
    let mut total = 0i64;
    total = total + (a * b);
    total = total + (a + b);
    total = total + (a - b);
    total = total + (a / b);
    total
}