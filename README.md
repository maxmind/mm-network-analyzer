# mm-network-analyzer

mm-network-analyzer collects data about the machine it is running on and
its network connection to help diagnose routing, DNS, and other issues to
MaxMind servers.

## Usage

Simply run `mm-network-analyzer`. No arguments are necessary.

After it completes, you will have `mm-network-analysis.zip` in your current
directory. It contains diagnostic information.

## Installation a release

Find a suitable archive for your system on the [Releases
tab](https://github.com/maxmind/mm-network-analyzer/releases). Extract the
archive. Inside is the `mm-network-analyzer` binary.

## Installation from source or Git

You need the Go compiler (Go 1.10+). You can get it at the [Go
website](https://golang.org).

The easiest way is via `go get`:

    $ go get -u github.com/maxmind/mm-network-analyzer

The program will be installed to `$GOPATH/bin/mm-network-analyzer`.

# Bug Reports

Please report bugs by filing an issue with our GitHub issue tracker at
https://github.com/maxmind/mm-network-analyzer/issues

# Copyright and License

This software is Copyright (c) 2018 - 2024 by MaxMind, Inc.

This is free software, licensed under the [Apache License, Version
2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT), at your option.
