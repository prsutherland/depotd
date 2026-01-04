use axum::{
    body::Body,
    http::{Response, StatusCode},
};

/// Create an XML error response
pub fn error_response(code: &str, message: &str, status: StatusCode) -> Response<Body> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>{}</Code>
  <Message>{}</Message>
</Error>"#,
        escape_xml(code),
        escape_xml(message)
    );
    Response::builder()
        .status(status)
        .header("Content-Type", "application/xml")
        .body(Body::from(xml))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        })
}

/// Create an XML success response for list buckets
pub fn list_buckets_response(buckets: &[String]) -> Response<Body> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
  <Buckets>
{}
  </Buckets>
</ListAllMyBucketsResult>"#,
        buckets
            .iter()
            .map(|b| format!("    <Bucket><Name>{}</Name></Bucket>", escape_xml(b)))
            .collect::<Vec<_>>()
            .join("\n")
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(Body::from(xml))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        })
}

/// Create an XML success response for list objects
pub fn list_objects_response(bucket: &str, objects: &[String]) -> Response<Body> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>{}</Name>
  <Contents>
{}
  </Contents>
</ListBucketResult>"#,
        escape_xml(bucket),
        objects
            .iter()
            .map(|o| format!("    <Key>{}</Key>", escape_xml(o)))
            .collect::<Vec<_>>()
            .join("\n")
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(Body::from(xml))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        })
}

/// Escape XML special characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
