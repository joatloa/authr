macro_rules! request {
    ($method:ident, $uri:expr) => {{
        actix_web::test::TestRequest::default()
            .method(actix_web::http::Method::$method)
            .uri($uri)
    }};
    ($method:ident, $uri:expr, json = $body:expr) => {{
        $crate::common::helpers::request!($method, $uri).set_json($body)
    }};
    ($method:ident, $uri:expr, headers = [$(($name:expr, $value:expr)),* $(,)?]) => {{
        let request = $crate::common::helpers::request!($method, $uri);
        $(let request = request.insert_header(($name, $value));)*
        request
    }};
    ($method:ident, $uri:expr, json = $body:expr, headers = [$(($name:expr, $value:expr)),* $(,)?]) => {{
        let request = $crate::common::helpers::request!($method, $uri).set_json($body);
        $(let request = request.insert_header(($name, $value));)*
        request
    }};
}
pub(crate) use request;

macro_rules! call {
    ($app:expr, $method:ident, $uri:expr) => {{
        let request = $crate::common::helpers::request!($method, $uri).to_request();
        actix_web::test::call_service(&$app, request).await
    }};
    ($app:expr, $method:ident, $uri:expr, json = $body:expr) => {{
        let request = $crate::common::helpers::request!($method, $uri, json = $body).to_request();
        actix_web::test::call_service(&$app, request).await
    }};
    ($app:expr, $method:ident, $uri:expr, headers = [$($headers:tt)*]) => {{
        let request = $crate::common::helpers::request!($method, $uri, headers = [$($headers)*]).to_request();
        actix_web::test::call_service(&$app, request).await
    }};
    ($app:expr, $method:ident, $uri:expr, json = $body:expr, headers = [$($headers:tt)*]) => {{
        let request = $crate::common::helpers::request!($method, $uri, json = $body, headers = [$($headers)*]).to_request();
        actix_web::test::call_service(&$app, request).await
    }};
}
pub(crate) use call;
