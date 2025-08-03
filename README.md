# TinyBGP: Go Library for BGP Speakers

[![Go Reference](https://pkg.go.dev/badge/github.com/msiegen/tinybgp.svg)](https://pkg.go.dev/github.com/msiegen/tinybgp)

TinyBGP is low-dependency library for building
[BGP](https://en.wikipedia.org/wiki/Border_Gateway_Protocol) speakers. If you're
a developer looking to integrate BGP into your [Go](https://go.dev/)
application, read on.

## Objective

TinyBGP takes care of the mundane transactional bits of maintaining BGP sessions
and routing tables, while giving your application full control over policies. We
provide sensible default behavior for simple uses, but make it easy to overide
the built-in logic for more advanced needs.

We are currently focused on eBGP use cases with IPv4 and IPv6 unicast addresses.

A key goal in TinyBGP is to leave choices about configuration methods or
observability to the user. We aim to keep the library free of any dependencies
related to these applications concerns, thus _tiny_.

## Project Status

We're in the early stages. TinyBGP is serving all internal and external routing
needs at [AS400930](https://bgp.tools/as/400930), a regional network with four
sites, three upstream providers, and numerous cycles in its internal topology.
It's working well for that.

There hasn't been much investment in features outside of the minimum viable core
logic yet. We've designed a simple but general API that should be capable of
long-term stability, but likely made some mistakes along the way. Currently
[v0 semantics](https://go.dev/doc/modules/version-numbers) apply and we *will*
make backwards-incompatible changes if doing so results in a better API.

If you're building a simple announce-only application for some static prefixes,
TinyBGP is likely all you need. Think something like
[kube-vip](https://kube-vip.io/) or
[lelastic](https://github.com/linode/lelastic), but with fewer dependencies.

If you want to program routes into a data plane, you'll need to combine TinyBGP
with another library such as [netlink](https://github.com/vishvananda/netlink).
TinyBGP provides iterators to notify your application of updated or withdrawn
routes, which you can then pass on to netlink.

## Comparision to Other Projects

### GoBGP

[GoBGP](https://github.com/osrg/gobgp) is a full-featured BGP implementation
that may be run as a standalone application or consumed as a library in your own
application. It includes a CLI and support for config files in TOML, YAML, JSON,
and HCL formats. When you use GoBGP as a library, your application inherits
these features and dependencies.

TinyBGP uses GoBGP's message parsing and serialization logic. Those parts are
low-dependency and do not pull in the CLI or any of the config parsers. Nothing
specific to GoBGP is exposed through TinyBGP's API, so it's possible to switch
to a different implementation in the future.

### BGPFix

[BGPFix](https://github.com/bgpfix/bgpfix) is a library for modifying BGP
sessions in-flight. It's meant to be used in conjunction with an existing BGP
speaker and its core concept is a pipe, not a routing table.

In contrast, TinyBGP is focused on managing a routing table and interconnecting
more than two peers. BGPFix is an _edge_ in a network topology and TinyBGP is
a _node_, if you will.

### CoreBGP

[CoreBGP](https://github.com/jwhited/corebgp) is a pluggable library for a BGP
speaker. It does not manage a routing table or send its own update messages,
instead delegating those responsibilities to the user.

In contrast, TinyBGP does do those things. CoreBGP provides a lower level API
and TinyBGP provides a higher level one.

## Notes
This is not an officially supported Google product.
