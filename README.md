apt-transport-s3-rust
=====================

This is a single executable apt-transport for s3:// urls written in Rust.

### Motivation

It was written to replace (the excellent) [apt-transport-s3][1] so that python
didn't need to be installed on systems that otherwise didn't require it. This
was important for provisioning AMIs where the _only_ apt repositories were
local s3 caches—installing python becomes an annoying chicken-and-egg
problem. This project simplifies the issue by adding just a single binary
download before apt can be used.

[1]: https://github.com/MayaraCloud/apt-transport-s3

Building
--------

    cargo build --release

Installing
----------

    strip target/release/apt-transport-s3
    cp target/release/apt-transport-s3 /usr/lib/apt/method/s3

Debugging
---------

     echo '600 URI Acquire
     URI: s3://my-bucket/my-key
     Filename: /tmp/output-file
     Last-Modified: Mon, 19 Jan 2015 07:28:00 GMT

     ' | APT_TRANSPORT_S3_DEBUG=1 cargo run

License
-------

Copyright © 2021 David Caldwell <david@porkrind.org>

MIT Licensed: See LICENSE file for details.
