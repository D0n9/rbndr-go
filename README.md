# rbndr
Simple DNS Rebinding Service

[English](README.md) | [简体中文](README_zh.md)

**Go refactor of [taviso/rbndr](https://github.com/taviso/rbndr).**

rbndr is a very simple, non-conforming, name server for testing software against DNS rebinding vulnerabilities. The server responds to queries by selecting one of the two addresses in the hostname (based on query ID) and returning it with a very low TTL.

## Build and run (Go)

```bash
go build -o rbndr .
./rbndr              # listen on UDP 53 (requires root)
./rbndr -port 5353   # listen on 5353 for testing without root
go test -v ./...     # run tests
```

### Self-hosting with a custom domain

You can deploy rbndr on your own server and use **any domain suffix** (not limited to rbndr.us). This matches the community request in [taviso/rbndr#10](https://github.com/taviso/rbndr/issues/10).

```bash
./rbndr -domain=rebind.example.com -port 53
```

Then hostnames follow the same format with your domain:

- `<ipv4-hex>.<ipv4-hex>.rebind.example.com`

Example: `7f000001.c0a80001.rebind.example.com` alternates between 127.0.0.1 and 192.168.0.1. You can use subdomains of any length (e.g. `7f000001.c0a80001.rebind.mycompany.co.uk` with `-domain=rebind.mycompany.co.uk`).

1. Point your domain’s NS (or a subdomain like `rebind.example.com`) to this server’s IP.
2. Run rbndr with `-domain=rebind.example.com` (or your chosen suffix).
3. Use `host` / `dig` or browsers against `7f000001.c0a80001.rebind.example.com` as usual.

Default `-domain` is `rbndr.us` for compatibility with the public service.

The original C implementation is in `legacy/rebinder.c`.

https://en.wikipedia.org/wiki/DNS_rebinding

DNS rebinding is a form of TOCTOU (time of check, time of use) vulnerability. You would use it if you have a service that uses "preflight" checks incorrectly to modify security properties. For example, consider a (fictional) browser plugin that has an api like this:

```
AllowUntrustedAccess("foobar.com");
SendArbitraryRequests("foobar.com");
```

And `AllowUntrustedAccess()` simply sends a preflight HTTP request to the host:

```
GET /CanIDisableSecurity HTTP/1.1
```

If the service returns 200, then the plugin allows the hostpage complete access to that hostname. This might be a security vulnerability, because you can specify a rbndr hostname that will switch between a host you control and a host you don't. The plugin might allow complete access to an arbitrary ip address (e.g. an internal service, or localhost) even if that service would not normally permit the preflight check.

This might sound unrealistic, but that's exactly how Adobe Flash, Oracle Java and lots of other products worked in the past, and many other products still work.

Read about how Adobe tried to resolve this problem in Flash here, https://www.adobe.com/devnet/flashplayer/articles/fplayer9_security.html

For software that is vulnerable to this class of attack, rbndr is an easy way to test without having to modify `/etc/hosts` or setup your own nameserver. If the software associates the result with just the *hostname* and not the hostname and ip address, then you can grant yourself access to any ip address. 

The format for hostnames is simply

```
<ipv4 in base-16>.<ipv4 in base-16>.rbndr.us
```

But you can use this website to convert from dotted quads if you prefer:

https://lock.cmpxchg8b.com/rebinder.html


For example, to switch between `127.0.0.1` and `192.168.0.1` you would encode them as dwords, and then use:

```
7f000001.c0a80001.rbndr.us
```

Let's test it out:

```
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 127.0.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 127.0.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 127.0.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 127.0.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1

```

As you can see, the server randomly returns one of the addresses. You might do something like this (in pseudo-code):

```
// Keep calling api until it resolves to the address you control and you get granted access
while (AllowUntrustedAccesss("7f000001.c0a80001.rbndr.us") != true)
  ;

// Access granted, now wait for it to re-bind
while (ConnectToPort("7f000001.c0a80001.rbndr.us", 123) != true)
 ;
 
 // Now you have access to localhost:123 even though localhost did not opt-in to reduced security.
 SomethingEvil();
```

