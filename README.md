#pnetlink

pnetlink - native [NetLink](https://en.wikipedia.org/wiki/Netlink) library for rust using libpnet

This fork adds, as of now:

- Getters for Routes and their parameters in ```pnetlink::packet::netlink::NetlinkConnection``` and ```pnetlink::packet::route::route```

- Getters for Rules and their parameters in ```pnetlink::packet::netlink::NetlinkConnection``` and ```pnetlink::packet::route::route```

## Building

The project builds fine with `cargo build`.

The tests are not thread safe. You must run `cargo test -- --test-threads=1`,
or you will get many `AddrInUse` errors.

Some of the tests require elevated permissions; either capabilities granted
to the test binary, or for the test procedure to run as `root`. These will
fail with a `PermissionDenied` error.

