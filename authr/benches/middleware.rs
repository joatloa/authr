mod helpers;

use actix_web::{App, test, web};
use authr::{core::auth::AuthrContext, database::adapter::DieselDatabase, http::router};

use criterion::{Criterion, criterion_group, criterion_main};

use crate::helpers::{config, database, fixtures};

fn middleware_benchmarks(c: &mut Criterion) {
    database::reset_database();

    let runtime = tokio::runtime::Runtime::new().unwrap();

    let database_url =
        std::env::var("AUTHR_BENCH_DATABASE_URL").expect("AUTHR_BENCH_DATABASE_URL must be set");

    let context = AuthrContext::new(database::database(), config::config(database_url));

    let session = runtime.block_on(async {
        let user = context.store().create_user(fixtures::user()).await.unwrap();

        context
            .store()
            .create_session(fixtures::session(user.id), true)
            .await
            .unwrap()
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

    c.bench_function("middleware/without_session", |b| {
        b.to_async(&runtime).iter(|| async {
            let req = test::TestRequest::get()
                .uri("/api/auth/list-sessions")
                .to_request();

            test::call_service(&app, req).await;
        });
    });

    c.bench_function("middleware/with_session", |b| {
        b.to_async(&runtime).iter(|| async {
            let req = test::TestRequest::get()
                .uri("/api/auth/list-sessions")
                .insert_header(("Cookie", format!("authr_session={}", session.token)))
                .to_request();

            test::call_service(&app, req).await;
        });
    });
}

criterion_group!(benches, middleware_benchmarks);
criterion_main!(benches);
