# CHANGELOG

## 1.1.0

- Fixed the lookup of the public IP address. The program now requests it over
  HTTPS from `updates.maxmind.com`, because the old endpoint on
  `geoip.maxmind.com` no longer works. If the lookup fails, the program now
  records an error instead of saving the error response as the IP address.
- The release binaries are built with the current Go release. The 1.0.4 binaries
  used Go 1.12.2.
- The macOS binaries now require macOS 13 Ventura or later, and the Linux
  binaries require Linux kernel 3.2 or later.
- Releases now include arm64 builds for Linux and macOS. They no longer include
  a macOS 386 build, because Go no longer supports it. The archive names
  changed. For example, `mm-network-analyzer_1.0.4_Linux_x86_64.tar.gz` is now
  `mm-network-analyzer_1.1.0_linux_amd64.tar.gz`.
- The project now uses Go modules. Go 1.25 or later is required to build from
  source.

## 1.0.4 (2019-05-21)

- Get /cdn-cgi/trace endpoint for Cloudflare troubleshooting

## 1.0.3 (2019-02-25)

- Curl host using HTTPS as well as HTTP.

## 1.0.2 (2019-01-07)

- Added `mtr` report fallback to support execution when the desired mode is
  unavailable. (Try for `--json`, `--report-wide`, and `--report --no-dns` in
  that order.)

## 1.0.1 (2018-08-17)

- Files are now in a directory inside release archives.

## 1.0.0 (2018-08-17)

- Initial release
