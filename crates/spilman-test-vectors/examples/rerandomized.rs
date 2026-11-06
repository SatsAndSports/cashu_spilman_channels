//! Print the independent rerandomized channel vector family.
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&spilman_test_vectors::rerandomized::vectors())
            .expect("reference JSON")
    );
}
