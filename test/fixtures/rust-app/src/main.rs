// Fixture: smallvec is used directly.
use smallvec::SmallVec;

fn main() {
    let mut v: SmallVec<[u8; 4]> = SmallVec::new();
    v.push(1);
    println!("{:?}", v);
}
