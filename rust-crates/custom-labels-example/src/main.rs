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
    let mut last_update = Instant::now();

    loop {
        custom_labels::with_label("l1", rand_str(), || {
            custom_labels::with_label("l2", rand_str(), || loop {
                if last_update.elapsed() >= Duration::from_secs(10) {
                    break;
                }
            })
        });
        last_update = Instant::now();
    }
}
