# KernelCI Storage Server

This is a simple storage server that supports file upload and download, with token based authentication.
It supports multiple backends, currently only Azure Blob is supported, to provide user transparent storage.
It caches the files in a local directory and serves them from there.
Range requests are supported, but only for start offset, end limit is not implemented yet.

## Configuration

The server is configured using toml configuration file, the default configuration file is `config.toml`.

```toml
jwt_secret="JWT_SECRET"
[azure]
account=""
key=""
container=""
sastoken=""
```

## API

### Upload

`POST /upload`

Upload a file to the server.

field path: the path to store the file in the server.
field file0: the file to upload.

### Download

`GET /path/to/file`

Download a file from the server.

