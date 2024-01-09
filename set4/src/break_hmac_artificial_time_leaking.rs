use super::hmac::sha1_hmac;
use axum::extract::State;
use axum::{
    extract::Query,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{de, Deserialize, Deserializer};
use set2::ecb_cbc_detection_oracle::generate_random_bytes;
use std::cmp::min;
use std::{fmt, str::FromStr};
use std::{thread, time};

use super::hmac;
// #[derive(Clone)]
// struct AppState {
//     key: Vec<u8>,
// }
//todo how the duration requirement changes after the 10/12th letter
#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000/test")
        .await
        .unwrap();
    axum::serve(listener, app()).await.unwrap();
}

fn app() -> Router {
    // let state = AppState {
    //     key: generate_random_bytes(10),
    // };
    let key = "fff".as_bytes().to_vec(); // generate_random_bytes(10);
    let sig = sha1_hmac(key.as_slice(), "file".as_bytes());
    // return sig.eq(&signature).to_string();
    println!("real signature{:?}", sig);
    Router::new().route("/", get(move |query_paramas| handler(query_paramas, key)))
    //.with_state(state)
}
async fn handler(Query(params): Query<Params>, key: Vec<u8>) -> String {
    // format!("{params:?}")
    // println!("The generated key:{:?}", key);
    // println!("The key {:?}", key);
    // println!("Params signature {:?}", params.signature);
    // println!("Params file {:?}", params.file);
    let file = params.file.unwrap(); //.as_bytes();
    let signature = params.signature.unwrap();
    let sig = sha1_hmac(key.as_slice(), file.as_bytes());
    // return sig.eq(&signature).to_string();
    // println!("real signature{:?}", sig);
    insecure_comparison(sig, signature).to_string()
}
pub fn insecure_comparison(s1: String, s2: String) -> bool {
    let fifty_millis = time::Duration::from_millis(100);
    // println!("{:?}", s1);
    // println!("{:?}", s2);
    for (_, (a, b)) in s1.as_bytes().iter().zip(s2.as_bytes().iter()).enumerate() {
        if *a != *b {
            return false;
        }
        thread::sleep(fifty_millis);
    }
    true
}
/// Serde deserialization decorator to map empty Strings to None,
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s).map_err(de::Error::custom).map(Some),
    }
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Params {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    file: Option<String>,
    signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_something() {
        let server = &app();
        let file = "file";
        let mut signature = "f36c5d1f76452fe2d48e733081e7799a57d74751".to_string();

        let mut fifty_millis: time::Duration = time::Duration::new(0, 0);
        // println!("{:?}", fifty_millis);
        // for i in 0_usize..40 {
        //     fifty_millis = fifty_millis + time::Duration::from_millis(50);
        //     println!("{:?}", fifty_millis);
        // }
        // return;

        for i in 0_usize..signature.len() {
            // for i in 0_usize..16 {
            fifty_millis = fifty_millis + time::Duration::from_millis(100);
            //signature.len() {
            // println!("Trying: {:?}", i);
            for j in "abcdef01234567890".chars() {
                let now = time::Instant::now();

                let _ = signature.replace_range(i..i + 1, j.to_string().as_str());

                let request = format!("file={file}&signature={signature}");
                send_request_get_body(request.as_str(), server).await;
                // println!("{:?}", signature);
                println!("now: {:?} {:?}", now.elapsed(), j);
                if now.elapsed() >= fifty_millis {
                    println!(
                        "{:?}",
                        signature[0..i + 1]
                            .as_bytes()
                            .iter()
                            .map(|x| *x as char)
                            .collect::<Vec<char>>()
                    );
                    break;
                }
            }
        }
        println!(
            "The real    signature: {:?}",
            "8b3168c6b78b5ff9bc3948324ccc06c229a873c9"
        );
        println!("The guessed signature: {:?}", signature);
    }
    async fn send_request_get_body(query: &str, app: &Router) -> String {
        let body = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body();
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }
}
