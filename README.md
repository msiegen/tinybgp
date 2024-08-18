# TinyBGP: Go Library for BGP Speakers

TinyBGP is low-dependency library for building
[BGP](https://en.wikipedia.org/wiki/Border_Gateway_Protocol) speakers. If you're
a developer looking to integrate BGP into your [Go](https://go.dev/)
application, read on.

## Objective

TinyBGP takes care of the mundane transactional bits of maintaining a BGP
session, while giving your application extensive control over policies. We
provide sensible default behavior for simple uses, but make it easy to overide
the built-in logic for more advanced needs.

We are currently focused on eBGP use cases with IPv4 and IPv6 unicast addresses.

A key goal in TinyBGP is to refrain from imposing a particular choice of
configuration methodology or approach to observability. These are application
concerns and we know how hard it is to integrate a library that made different
choices than what you prefer in your environment. TinyBGP is configured through
an idiomatic Go API and exposes hooks for you to bring your own observability.

## Project Status

We're just starting out! The current focus is on building a minimum viable
implementation of the core logic, and on designing a simple but general API that
can achieve long-term stability. In this phase
[v0 semantics](https://go.dev/doc/modules/version-numbers) apply and we *will*
make backwards-incompatible API changes.

If that sounds good, it's possible to build simple announce-only applications
with TinyBGP today. Think something like [kube-vip](https://kube-vip.io/) or
[lelastic](https://github.com/linode/lelastic). Observability is still lacking
compared to what GoBGP (used in the above projects) provides, and connecting
TinyBGP as a non-leaf node is unsupported (but coming soon).

## Relation to GoBGP

TinyBGP is not affiliated with [GoBGP](https://github.com/osrg/gobgp), but we
are inspired by what they've shown is possible and leverage their work where it
makes sense.

### Comparision

GoBGP is a full-featured BGP implementation that may be run as a standalone
application or consumed as a library in your own application. It includes a CLI
and support for config files in TOML, YAML, JSON, and HCL formats. When you use
GoBGP as a library, your application inherits these features and dependencies.

TinyBGP is a library-only, from-scratch implementation of a BGP speaker (the
client and server bits). But we don't want to reinvent all the wheels! We reuse
the message parsing and serialization logic from GoBGP because it works well and
doesn't add any unwanted dependencies.

## Notes
This is not an officially supported Google product.
