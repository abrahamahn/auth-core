use auth_password_argon2::{Argon2Config, Argon2Variant, needs_rehash, verify_password};
use serde_json::Value;

#[test]
fn verifies_the_shared_typescript_argon2id_vector() {
    let vectors: Value = serde_json::from_str(include_str!("../fixtures/password-vectors.json"))
        .expect("valid vectors");
    let vector = &vectors["argon2id"];
    let password = vector["password"].as_str().expect("password");
    let phc = vector["phc"].as_str().expect("phc");
    let config = &vector["config"];
    let config = Argon2Config {
        memory_cost: u32::try_from(config["memoryCost"].as_u64().expect("memory cost"))
            .expect("u32 memory cost"),
        time_cost: u32::try_from(config["timeCost"].as_u64().expect("time cost"))
            .expect("u32 time cost"),
        parallelism: u32::try_from(config["parallelism"].as_u64().expect("parallelism"))
            .expect("u32 parallelism"),
        variant: Argon2Variant::Argon2id,
    };

    assert!(verify_password(password, phc));
    assert!(!needs_rehash(phc, config));
}
