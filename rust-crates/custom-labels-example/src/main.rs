use std::time::{Duration, Instant};

use rand::distr::Alphanumeric;
use rand::Rng;

fn rand_str() -> String {
    String::from_utf8(
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn main() {
    let start = Instant::now();

    custom_labels::with_label("l1", rand_str(), || {
        custom_labels::with_label("l2", rand_str(), || loop {
            if start.elapsed() >= Duration::from_secs(10) {
                println!("PASS");
                return;
            }
        })
    });
}
