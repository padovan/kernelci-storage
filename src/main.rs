// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2024 Collabora, Ltd.
// Author: Denys Fedoryshchenko <denys.f@collabora.com>
/*
   KernelCI Storage Server

   This is a simple storage server that supports file upload and download, with token based authentication.
   It supports multiple backends, currently only Azure Blob is supported, to provide user transparent storage.
   It caches the files in a local directory and serves them from there.
   Range requests are supported, but only for start offset, end limit is not implemented yet.
*/

mod azure;
mod storjwt;

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path},
    http::{header, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use headers::HeaderMap;
use std::{net::SocketAddr, path::PathBuf};
use tokio::io::AsyncSeekExt;
use tokio_util::io::ReaderStream;
use toml::Table;

const TOKEN: &str = "SuperSecretToken";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "./", help = "Directory to store files")]
    files_directory: String,

    #[clap(
        short,
        long,
        default_value = "./ssl",
        help = "Directory with cert.pem and key.pem"
    )]
    ssl_directory: String,

    #[clap(
        short,
        long,
        default_value = "./config.toml",
        help = "Config file, relative to files_directory"
    )]
    config_file: String,
}

struct ReceivedFile {
    original_filename: String,
    cached_filename: String,
    headers: HeaderMap,
    valid: bool,
}

trait Driver {
    fn write_file(&self, filename: String, data: Vec<u8>) -> &str;
    fn get_file(&self, filename: String) -> ReceivedFile;
}

fn init_driver(driver_type: &str) -> Box<dyn Driver> {
    let driver: Box<dyn Driver> = match driver_type {
        "azure" => Box::new(azure::AzureDriver::new()),
        //"google" => Box::new(google::GoogleDriver::new()),
        _ => {
            eprintln!("Unknown driver type");
            std::process::exit(1);
        }
    };
    return driver;
}

/// Initial variables configuration and checks
async fn initial_setup() -> Option<RustlsConfig> {
    let cache_dir = "cache";
    let download_dir = "download";
    let args = Args::parse();

    if let Err(e) = std::env::set_current_dir(&args.files_directory) {
        eprintln!("Error changing directory: {}", e);
        std::process::exit(1);
    }

    if !std::path::Path::new(cache_dir).exists() {
        std::fs::create_dir(cache_dir).unwrap();
    }
    if !std::path::Path::new(download_dir).exists() {
        std::fs::create_dir(download_dir).unwrap();
    }
    if !std::path::Path::new(&args.config_file).exists() {
        eprintln!("Config file {} does not exist", &args.config_file);
        std::process::exit(1);
    }

    let config = RustlsConfig::from_pem_file(
        PathBuf::from(&args.ssl_directory).join("cert.pem"),
        PathBuf::from(&args.ssl_directory).join("key.pem"),
    )
    .await;
    match config {
        Ok(tlsconf) => {
            println!("TLS config loaded");
            Some(tlsconf)
        }
        Err(e) => {
            eprintln!("Error reading TLS config: {:?}", e);
            None
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let tlscfg = initial_setup().await;
    let port = 3000;
    println!("Starting server, tls: {:?}", tlscfg);

    // Supported endpoints:
    // GET / - root
    // GET /v1/checkauth - check if the token is correct
    // POST /v1/file and /upload - upload file
    // GET /*filepath - get file
    let app = Router::new()
        .route("/", get(root))
        .route("/v1/checkauth", get(ax_check_auth))
        .route("/v1/file", post(ax_post_file))
        .route("/upload", post(ax_post_file))
        .route("/*filepath", get(ax_get_file))
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024 * 4));

    if let Some(tlscfg) = tlscfg {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        let listener = axum_server::bind_rustls(addr, tlscfg)
            .serve(app.into_make_service())
            .await
            .unwrap();
    } else {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}

async fn root() -> &'static str {
    "KernelCI Storage Server"
}

/// Check if the Authorization header is present and if the token is correct    
/// Test it by: curl -X GET http://localhost:3000/v1/checkauth -H "Authorization: Bearer SuperSecretToken"
async fn ax_check_auth(headers: HeaderMap) -> (StatusCode, &'static str) {
    let message = verify_auth_hdr(&headers);

    if message == "" {
        (StatusCode::OK, "Authorized")
    } else {
        (StatusCode::UNAUTHORIZED, message)
    }
}

/*
    Upload file from user to remote storage
    TBD: Store file in cache as well?

    curl -X POST http://localhost:3000/v1/file -H "Authorization Bearer SuperSecretToken" -F "filename=@test.bin"

    This function will check if the Authorization header is present and if the token is correct
    If the token is correct, it will write the content of the file to the server
*/
async fn ax_post_file(headers: HeaderMap, mut multipart: Multipart) -> (StatusCode, Vec<u8>) {
    // call check_auth
    let message = verify_auth_hdr(&headers);
    // return status and message
    if message != "" {
        return (StatusCode::UNAUTHORIZED, Vec::new());
    }
    println!("Authorized");

    /* 100-continue Expect is broken, quite hard to fix in axum */
    /*
    if let Some(expect) = headers.get("Expect") {
        println!("Expect: {:?}", expect);
        if expect == "100-continue" {
            println!("Expect 100-continue");
            return (StatusCode::CONTINUE, Vec::new());
        }
    }
    */

    println!("Uploading file");
    let mut path: String = "".to_string();
    let mut file0: Vec<u8> = Vec::new();
    let mut file0_filename: String = "".to_string();

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();
        //let filename = field.file_name();
        let filename = field.file_name().map(|f| f.to_string()); // Map filename to avoid borrowing later, how this black magic works?!?!?!
        let data = field.bytes().await;

        match data {
            Ok(data) => {
                println!("Length of `{}` is {} bytes", name, data.len());
                if name == "path" {
                    path = String::from_utf8(data.to_vec()).unwrap();
                    println!("Path: {}", path);
                } else if name == "file0" {
                    file0 = data.to_vec();
                    match filename {
                        Some(filename) => file0_filename = filename.to_string(),
                        None => todo!(),
                    }
                } else {
                    println!("Unknown field: {} len: {}", name, data.len());
                }
            }
            Err(e) => {
                eprintln!(
                    "Error reading file: {:?} for name {}. Axum size upload limit?",
                    e, name
                );
                return (StatusCode::BAD_REQUEST, Vec::new());
            }
        }
    }
    println!(
        "File: {} bytes filename: {} path: {}",
        file0.len(),
        file0_filename,
        path
    );
    // if path ends on /, remove it
    if path.ends_with("/") {
        // TBD: Fix it!
        println!("Removing trailing /, workaround");
        path.pop();
    }
    let full_path = format!("{}/{}", path, file0_filename);
    let message = write_file_driver(full_path, file0);
    if message != "" {
        return (StatusCode::CONFLICT, Vec::new());
    }
    (StatusCode::OK, Vec::new())
}

/*
    Retrieve file in the server from the cache/storage and return it to the client

    curl -X GET http://localhost:3000/v1/file/test.bin -H "Authorization: Bearer SuperSecretToken"

    This function will check if the Authorization header is present and if the token is correct
    If the token is correct, it will return the content of the file u8

*/
async fn ax_get_file(
    Path(filepath): Path<String>,
    rxheaders: HeaderMap,
    method: Method,
) -> impl IntoResponse {
    let received_file = driver_get_file(filepath.clone());
    if !received_file.valid {
        return (StatusCode::NOT_FOUND, format!("Not Found: {}", filepath)).into_response();
    }
    let cached_file = received_file.cached_filename;
    let original_filename = received_file.original_filename;
    //let file: tokio::fs::File;
    let metadata = tokio::fs::metadata(&cached_file).await.unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", &original_filename)
            .parse()
            .unwrap(),
    );
    headers.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());

    /* Usually HEAD is used to check if the file exists and range is supported */
    if method == axum::http::Method::HEAD {
        println!("HEAD request, returning headers only");
        return (headers, Body::empty()).into_response();
    }
    match tokio::fs::File::open(&cached_file).await {
        Ok(mut file) => {
            let mut start = 0;
            let mut end = metadata.len();
            // is Content-Range present?
            if let Some(range) = rxheaders.get("Range") {
                println!("Range: {:?}", range);
                (start, end) = parse_range(range.to_str().unwrap());
            }
            // if start is set to non-zero, we need to seek
            if start != 0 && (end == metadata.len() || end == 0) {
                println!("Seeking to {}", start);
                file.seek(std::io::SeekFrom::Start(start)).await.unwrap();
                headers.insert(
                    header::CONTENT_RANGE,
                    format!("bytes {}-", start).parse().unwrap(),
                );
                if end == 0 || end >= metadata.len() {
                    end = metadata.len();
                }
                headers.insert(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end - 1, metadata.len())
                        .parse()
                        .unwrap(),
                );
                headers.insert(
                    header::CONTENT_LENGTH,
                    format!("{}", end - start).parse().unwrap(),
                );
            } else {
                headers.insert(
                    header::CONTENT_LENGTH,
                    format!("{}", metadata.len()).parse().unwrap(),
                );
            }
            // If end... who cares about end :-D
            // Well, we need to implement it
            // TODO: implement "end" limit
            let stream = ReaderStream::new(file);
            let axbody = Body::from_stream(stream);

            println!("Headers: {:?}", headers);
            if start != 0 {
                return (StatusCode::PARTIAL_CONTENT, headers, axbody).into_response();
            }
            return (StatusCode::OK, headers, axbody).into_response();
        }
        Err(_) => {
            println!("Error opening file in ax_get_file");
            return (StatusCode::NOT_FOUND, headers, Body::empty()).into_response();
        }
    };
}

fn driver_get_file(filepath: String) -> ReceivedFile {
    let driver_name = "azure";
    let driver = init_driver(driver_name);
    return driver.get_file(filepath);
}

fn write_file_driver(filename: String, data: Vec<u8>) -> &'static str {
    let driver_name = "azure";
    let driver = init_driver(driver_name);
    driver.write_file(filename, data);
    return "";
}

/// Parse range header
/// We support limited range only for now
fn parse_range(range: &str) -> (u64, u64) {
    let parts: Vec<&str> = range.split("=").collect();
    let range_parts: Vec<&str> = parts[1].split("-").collect();
    let start = range_parts[0].parse::<u64>().unwrap();
    if range_parts.len() == 1 {
        return (start, 0);
    }
    let end = range_parts[1].parse::<u64>();
    match end {
        Ok(end) => return (start, end),
        Err(_) => return (start, 0),
    }
}

/// Verify the Authorization header
fn verify_auth_hdr(headers: &HeaderMap) -> &'static str {
    let auth = headers.get("Authorization");
    match auth {
        None => return "No Authorization Header",
        _ => (),
    }
    let token = auth.unwrap().to_str().unwrap().split_whitespace();
    let token_parts: Vec<&str> = token.collect();
    if token_parts.len() != 2 {
        let verif_result = storjwt::verify_jwt_token(token_parts[0]);
        match verif_result {
            Ok(_) => return "",
            Err(_) => {
                println!("Error verifying token");
                return "Invalid Token";
            }
        }

        // We have auth without "Bearer" prefix
        // This is what KernelCI uses :(, so we need to support it
        if token_parts.len() == 1 && token_parts[0] == TOKEN {
            return "";
        } else {
            return "Invalid Token or format";
        }
    }
    let verif_result = storjwt::verify_jwt_token(token_parts[1]);
    match verif_result {
        Ok(_) => return "",
        Err(_) => {
            println!("Error verifying bearer token");
            return "Invalid Token";
        }
    }
    if token_parts[1] != TOKEN {
        return "Invalid Token";
    } else {
        return "";
    }
}
