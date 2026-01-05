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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn test_error_response() {
        let response = error_response("TestError", "Test message", StatusCode::BAD_REQUEST);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("<Code>TestError</Code>"));
        assert!(body_str.contains("<Message>Test message</Message>"));
    }

    #[tokio::test]
    async fn test_list_buckets_response() {
        let buckets = vec!["bucket1".to_string(), "bucket2".to_string()];
        let response = list_buckets_response(&buckets);
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("<Name>bucket1</Name>"));
        assert!(body_str.contains("<Name>bucket2</Name>"));
    }

    #[tokio::test]
    async fn test_list_objects_response() {
        let objects = vec!["file1.txt".to_string(), "file2.txt".to_string()];
        let response = list_objects_response("test-bucket", &objects);
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("<Name>test-bucket</Name>"));
        assert!(body_str.contains("<Key>file1.txt</Key>"));
        assert!(body_str.contains("<Key>file2.txt</Key>"));
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("test"), "test");
        assert_eq!(escape_xml("a & b"), "a &amp; b");
        assert_eq!(escape_xml("a < b"), "a &lt; b");
        assert_eq!(escape_xml("a > b"), "a &gt; b");
        assert_eq!(escape_xml(r#"a "b" c"#), "a &quot;b&quot; c");
        assert_eq!(escape_xml("a 'b' c"), "a &apos;b&apos; c");
    }
}
