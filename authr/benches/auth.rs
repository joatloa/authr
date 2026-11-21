mod helpers;

use actix_web::{App, test, web};
use authr::{
    core::{auth::AuthrContext, types::Account, utils::hash_password_async},
    database::adapter::DieselDatabase,
    http::router,
};

use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;
use tokio::runtime::Runtime;

use helpers::{config, database, fixtures};

const SIGN_IN_USER_COUNT: usize = 128;
const BENCH_PASSWORD: &str = "benchmark-password";

fn auth_benchmarks(c: &mut Criterion) {
    database::reset_database();

    let runtime = Runtime::new().unwrap();

    let database_url =
        std::env::var("AUTHR_BENCH_DATABASE_URL").expect("AUTHR_BENCH_DATABASE_URL must be set");

    let context = AuthrContext::new(database::database(), config::config(database_url));

    // Prepare sign-in users outside the measured benchmarks.
    let (users, password) = runtime.block_on(async {
        let password = BENCH_PASSWORD.to_string();

        let password_hash = hash_password_async(context.argon().clone(), password.clone())
            .await
            .unwrap();

        let mut users = Vec::with_capacity(SIGN_IN_USER_COUNT);

        for _ in 0..SIGN_IN_USER_COUNT {
            let user = context.store().create_user(fixtures::user()).await.unwrap();

            context
                .store()
                .create_account(Account::new_credential(user.id, password_hash.clone()))
                .await
                .unwrap();

            users.push(user);
        }

        (users, password)
    });

    let app = runtime.block_on(async {
        let context = web::Data::new(context);

        test::init_service(
            App::new()
                .app_data(context)
                .service(web::scope("/api/auth").configure(router::config::<DieselDatabase>)),
        )
        .await
    });

    // ---- Sign up

    c.bench_function("auth/sign_up", |b| {
        b.to_async(&runtime).iter(|| async {
            let req = test::TestRequest::post()
                .uri("/api/auth/sign-up")
                .set_json(json!({
                    "name": "Benchmark User",
                    "email": format!(
                        "{}@benchmark.local",
                        uuid::Uuid::new_v4()
                    ),
                    "password": BENCH_PASSWORD,
                    "rememberMe": true
                }))
                .to_request();

            let response = test::call_service(&app, req).await;

            assert!(
                response.status().is_success(),
                "Sign-up failed with status: {}",
                response.status()
            );
        });
    });

    // ---- Email sign in

    let mut user_index = 0usize;

    c.bench_function("auth/sign_in_email", |b| {
        b.to_async(&runtime).iter(|| {
            let user = &users[user_index % users.len()];
            user_index += 1;

            async {
                let req = test::TestRequest::post()
                    .uri("/api/auth/sign-in/email")
                    .set_json(json!({
                        "email": user.email.clone(),
                        "password": password.clone(),
                        "rememberMe": true
                    }))
                    .to_request();

                let response = test::call_service(&app, req).await;

                assert!(
                    response.status().is_success(),
                    "Sign-in failed with status: {}",
                    response.status()
                );
            }
        });
    });
}

criterion_group!(benches, auth_benchmarks);
criterion_main!(benches);
