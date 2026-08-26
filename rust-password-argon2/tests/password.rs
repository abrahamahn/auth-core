use auth_password_argon2::{
    Argon2Config, Argon2Variant, DummyHashPool, hash_password, needs_rehash, verify_password,
};

fn fast_config() -> Argon2Config {
    Argon2Config {
        memory_cost: 1_024,
        time_cost: 2,
        parallelism: 1,
        variant: Argon2Variant::Argon2id,
    }
}

#[test]
fn hashes_verifies_and_detects_parameter_upgrades() {
    let config = fast_config();
    let hash = hash_password("correct horse battery staple", config).expect("hash");

    assert!(hash.starts_with("$argon2id$v=19$m=1024,t=2,p=1$"));
    assert!(verify_password("correct horse battery staple", &hash));
    assert!(!verify_password("wrong password", &hash));
    assert!(!needs_rehash(&hash, config));
    assert!(needs_rehash(
        &hash,
        Argon2Config {
            memory_cost: 2_048,
            ..config
        }
    ));
}

#[test]
fn malformed_hashes_fail_closed() {
    assert!(!verify_password("password", "not-a-phc-string"));
    assert!(needs_rehash("not-a-phc-string", fast_config()));
}

#[test]
fn dummy_pool_equalizes_unknown_account_verification() {
    let config = fast_config();
    let pool = DummyHashPool::new(config, 2).expect("pool");
    pool.initialize().expect("initialize");
    pool.initialize().expect("idempotent initialize");
    assert!(pool.is_initialized().expect("status"));

    let known_hash = hash_password("known password", config).expect("hash");
    assert!(
        pool.verify("known password", Some(&known_hash))
            .expect("verify")
    );
    assert!(
        !pool
            .verify("wrong password", Some(&known_hash))
            .expect("verify")
    );
    assert!(!pool.verify("any password", None).expect("dummy verify"));

    pool.reset().expect("reset");
    assert!(!pool.is_initialized().expect("status"));
    assert!(!pool.verify("any password", None).expect("fallback verify"));
}
