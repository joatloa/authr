mod helpers;

use std::hint::black_box;

use authr::core::{
    secrets::derive_secrets,
    utils::{create_argon, hash_password_async, verify_password_async},
};
use criterion::{Criterion, criterion_group, criterion_main};

use crate::helpers::config::BENCH_SECRET;

fn crypto_benchmarks(c: &mut Criterion) {
    c.bench_function("crypto/derive_secrets", |b| {
        b.iter(|| derive_secrets(black_box(BENCH_SECRET)));
    });

    let secrets = derive_secrets(BENCH_SECRET);

    c.bench_function("crypto/hash_session_token", |b| {
        b.iter(|| {
            secrets.hash_session_token(black_box("benchmark-session-token"));
        });
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let argon = create_argon();
    let password = "benchmark-password".to_string();

    // Prepare the hash outside the timed verification benchmark.
    let password_hash = runtime.block_on(async {
        hash_password_async(argon.clone(), password.clone())
            .await
            .unwrap()
    });

    c.bench_function("crypto/hash_password", |b| {
        b.to_async(&runtime).iter(|| async {
            hash_password_async(argon.clone(), password.clone())
                .await
                .unwrap();
        });
    });

    c.bench_function("crypto/verify_password", |b| {
        b.to_async(&runtime).iter(|| async {
            verify_password_async(password.clone(), password_hash.clone())
                .await
                .unwrap();
        });
    });
}

criterion_group!(benches, crypto_benchmarks);
criterion_main!(benches);
