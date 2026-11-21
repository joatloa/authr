mod helpers;

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

use authr::{
    core::{
        auth::AuthrStore,
        secrets::derive_secrets,
        types::{Account, Session, User, Verification},
    },
    database::adapter::DieselDatabase,
};

use helpers::{config::BENCH_SECRET, database, fixtures};

// ---- Helpers

fn create_store() -> AuthrStore<DieselDatabase> {
    AuthrStore::new(database::database(), Arc::new(derive_secrets(BENCH_SECRET)))
}

async fn create_user(store: &AuthrStore<DieselDatabase>) -> User {
    store.create_user(fixtures::user()).await.unwrap()
}

async fn create_account(store: &AuthrStore<DieselDatabase>, user_id: uuid::Uuid) -> Account {
    store
        .create_account(fixtures::account(user_id))
        .await
        .unwrap()
}

async fn create_session(store: &AuthrStore<DieselDatabase>, user_id: uuid::Uuid) -> Session {
    store
        .create_session(fixtures::session(user_id), true)
        .await
        .unwrap()
}

async fn create_verification(store: &AuthrStore<DieselDatabase>) -> Verification {
    store
        .create_verification(fixtures::verification())
        .await
        .unwrap()
}

/// Runs asynchronous setup before starting the timer, then measures only
/// the asynchronous operation.
fn bench_with_setup<T, Setup, SetupFuture, Operation, OperationFuture>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    runtime: &Runtime,
    name: &str,
    mut setup: Setup,
    mut operation: Operation,
) where
    Setup: FnMut() -> SetupFuture,
    SetupFuture: std::future::Future<Output = T>,
    Operation: FnMut(T) -> OperationFuture,
    OperationFuture: std::future::Future<Output = ()>,
{
    group.bench_function(name, |b| {
        b.iter_custom(|iterations| {
            runtime.block_on(async {
                let mut elapsed = Duration::ZERO;

                for _ in 0..iterations {
                    let input = setup().await;

                    let start = Instant::now();
                    operation(input).await;
                    elapsed += start.elapsed();
                }

                elapsed
            })
        });
    });
}

// ---- Users

fn user_benchmarks(c: &mut Criterion, runtime: &Runtime, store: &AuthrStore<DieselDatabase>) {
    let mut group = c.benchmark_group("database/users");

    group.bench_function("create", |b| {
        b.to_async(runtime).iter(|| async {
            create_user(store).await;
        });
    });

    let user = runtime.block_on(create_user(store));

    group.bench_function("find_by_id", |b| {
        b.to_async(runtime).iter(|| async {
            store.find_user_by_id(&user.id.to_string()).await.unwrap();
        });
    });

    group.bench_function("find_by_email", |b| {
        b.to_async(runtime).iter(|| async {
            store.find_user_by_email(&user.email).await.unwrap();
        });
    });

    group.bench_function("update", |b| {
        b.to_async(runtime).iter(|| {
            let mut updated = user.clone();
            updated.name = "Updated Benchmark User".into();
            updated.updated_at = Utc::now();

            async move {
                store.update_user(updated).await.unwrap();
            }
        });
    });

    bench_with_setup(
        &mut group,
        runtime,
        "delete_by_id",
        || create_user(store),
        |user| async move {
            store.delete_user_by_id(&user.id.to_string()).await.unwrap();
        },
    );

    bench_with_setup(
        &mut group,
        runtime,
        "delete_by_email",
        || create_user(store),
        |user| async move {
            store.delete_user_by_email(&user.email).await.unwrap();
        },
    );

    group.finish();
}

// ---- Sessions

fn session_benchmarks(c: &mut Criterion, runtime: &Runtime, store: &AuthrStore<DieselDatabase>) {
    let mut group = c.benchmark_group("database/sessions");

    let user = runtime.block_on(create_user(store));

    group.bench_function("create", |b| {
        b.to_async(runtime).iter(|| async {
            create_session(store, user.id).await;
        });
    });

    let session = runtime.block_on(create_session(store, user.id));

    group.bench_function("find_by_token", |b| {
        b.to_async(runtime).iter(|| async {
            store.find_session_by_token(&session.token).await.unwrap();
        });
    });

    group.bench_function("find_by_user_id", |b| {
        b.to_async(runtime).iter(|| async {
            store
                .find_sessions_by_user_id(&user.id.to_string())
                .await
                .unwrap();
        });
    });

    group.bench_function("find_other_sessions", |b| {
        b.to_async(runtime).iter(|| async {
            store
                .find_other_sessions(&user.id.to_string(), &session.id.to_string())
                .await
                .unwrap();
        });
    });

    group.bench_function("update", |b| {
        b.to_async(runtime).iter(|| {
            let mut updated = session.clone();
            updated.updated_at = Utc::now();

            async move {
                store.update_session(updated).await.unwrap();
            }
        });
    });

    bench_with_setup(
        &mut group,
        runtime,
        "delete_by_token",
        || create_session(store, user.id),
        |session| async move {
            store.delete_session_by_token(&session.token).await.unwrap();
        },
    );

    bench_with_setup(
        &mut group,
        runtime,
        "delete_user_sessions",
        || async {
            let user = create_user(store).await;
            create_session(store, user.id).await;
            create_session(store, user.id).await;
            user
        },
        |user| async move {
            store
                .delete_user_sessions(&user.id.to_string())
                .await
                .unwrap();
        },
    );

    bench_with_setup(
        &mut group,
        runtime,
        "delete_other_sessions",
        || async {
            let user = create_user(store).await;
            let current = create_session(store, user.id).await;
            create_session(store, user.id).await;

            (user, current)
        },
        |(user, current)| async move {
            store
                .delete_other_sessions(&user.id.to_string(), &current.id.to_string())
                .await
                .unwrap();
        },
    );

    group.finish();
}

// ---- Accounts

fn account_benchmarks(c: &mut Criterion, runtime: &Runtime, store: &AuthrStore<DieselDatabase>) {
    let mut group = c.benchmark_group("database/accounts");

    bench_with_setup(
        &mut group,
        runtime,
        "create",
        || create_user(store),
        |user| async move {
            create_account(store, user.id).await;
        },
    );

    let user = runtime.block_on(create_user(store));
    let account = runtime.block_on(create_account(store, user.id));

    group.bench_function("find_by_id", |b| {
        b.to_async(runtime).iter(|| async {
            store
                .find_account_by_id(&account.id.to_string())
                .await
                .unwrap();
        });
    });

    group.bench_function("find_by_provider", |b| {
        b.to_async(runtime).iter(|| async {
            store
                .find_account_by_provider(&account.provider_id, &account.account_id)
                .await
                .unwrap();
        });
    });

    group.bench_function("find_by_user_id", |b| {
        b.to_async(runtime).iter(|| async {
            store
                .find_account_by_user_id(&user.id.to_string())
                .await
                .unwrap();
        });
    });

    group.bench_function("find_many_by_user_id", |b| {
        b.to_async(runtime).iter(|| async {
            store
                .find_accounts_by_user_id(&user.id.to_string())
                .await
                .unwrap();
        });
    });

    group.bench_function("update", |b| {
        b.to_async(runtime).iter(|| {
            let mut updated = account.clone();
            updated.updated_at = Utc::now();

            async move {
                store.update_account(updated).await.unwrap();
            }
        });
    });

    bench_with_setup(
        &mut group,
        runtime,
        "delete_by_id",
        || async {
            let user = create_user(store).await;
            create_account(store, user.id).await
        },
        |account| async move {
            store
                .delete_account_by_id(&account.id.to_string())
                .await
                .unwrap();
        },
    );

    bench_with_setup(
        &mut group,
        runtime,
        "delete_by_user_id",
        || async {
            let user = create_user(store).await;
            create_account(store, user.id).await;
            user
        },
        |user| async move {
            store
                .delete_accounts_by_user_id(&user.id.to_string())
                .await
                .unwrap();
        },
    );

    group.finish();
}

// ---- Verifications

fn verification_benchmarks(
    c: &mut Criterion,
    runtime: &Runtime,
    store: &AuthrStore<DieselDatabase>,
) {
    let mut group = c.benchmark_group("database/verifications");

    group.bench_function("create", |b| {
        b.to_async(runtime).iter(|| async {
            create_verification(store).await;
        });
    });

    let verification = runtime.block_on(create_verification(store));

    group.bench_function("find_by_id", |b| {
        b.to_async(runtime).iter(|| async {
            store
                .find_verification_by_id(&verification.id.to_string())
                .await
                .unwrap();
        });
    });

    group.bench_function("find_by_identifier", |b| {
        b.to_async(runtime).iter(|| async {
            store
                .find_verification_by_identifier(&verification.identifier)
                .await
                .unwrap();
        });
    });

    group.bench_function("update", |b| {
        b.to_async(runtime).iter(|| {
            let mut updated = verification.clone();
            updated.value = "updated-benchmark-value".into();
            updated.updated_at = Utc::now();

            async move {
                store.update_verification(updated).await.unwrap();
            }
        });
    });

    bench_with_setup(
        &mut group,
        runtime,
        "delete_by_id",
        || create_verification(store),
        |verification| async move {
            store
                .delete_verification_by_id(&verification.id.to_string())
                .await
                .unwrap();
        },
    );

    bench_with_setup(
        &mut group,
        runtime,
        "delete_by_identifier",
        || create_verification(store),
        |verification| async move {
            store
                .delete_verification_by_identifier(&verification.identifier)
                .await
                .unwrap();
        },
    );

    bench_with_setup(
        &mut group,
        runtime,
        "consume",
        || create_verification(store),
        |verification| async move {
            store
                .consume_verification(&verification.identifier)
                .await
                .unwrap();
        },
    );

    group.finish();
}

// ---- Entry point

fn database_benchmarks(c: &mut Criterion) {
    database::reset_database();

    let runtime = Runtime::new().unwrap();
    let store = create_store();

    user_benchmarks(c, &runtime, &store);
    session_benchmarks(c, &runtime, &store);
    account_benchmarks(c, &runtime, &store);
    verification_benchmarks(c, &runtime, &store);
}

criterion_group!(benches, database_benchmarks);
criterion_main!(benches);
