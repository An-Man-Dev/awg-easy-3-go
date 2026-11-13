# Third-party notices

Original project code is licensed under the MIT License in `LICENSE`.
This grant does not relicense any third-party component listed below.

This is an independently implemented Go control plane. The legacy JavaScript
project in `awg-easy-3/` was consulted solely for interoperability details. Its
implementation and assets are not part of the new application or Docker context.
That directory retains its existing ownership and licensing terms and is
excluded from this Git repository as well as the Docker build context.

## Acknowledgements and independence

We thank the authors and contributors of
[alexsemenovru/awg-easy-3](https://github.com/alexsemenovru/awg-easy-3) for the
inspiration and interoperability reference, and
[JohnnyVBut/awg-easy](https://github.com/JohnnyVBut/awg-easy), its upstream project.
This application has its own Go implementation and architecture; it is not
maintained as a direct code fork of those panels. Their code, assets, and licenses
remain with their respective projects.

We also thank the AmneziaVPN and AmneziaWG contributors for the official protocol
implementations and tools. This is an independent, non-commercial hobby project.
It is not affiliated with, sponsored by, or endorsed by Amnezia or the AmneziaVPN
team. Project names are used to identify compatibility and acknowledge their
work. The non-commercial purpose does not restrict the permissions granted by
the MIT License for this project's original code.

## Runtime components

| Component | Revision | License | Authoritative source |
| --- | --- | --- | --- |
| AmneziaWG Go | `b5928efb6ca19f0153958460c3d141f04abc5c2e` | MIT | https://github.com/amnezia-vpn/amneziawg-go |
| AmneziaWG Tools | `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` | See upstream COPYING and individual file headers (GPL-2.0 / MIT) | https://github.com/amnezia-vpn/amneziawg-tools |
| go-qrcode | `da1b6568686e` | MIT | https://github.com/skip2/go-qrcode |
| Go runtime and standard library | Go 1.25 builder toolchain | BSD-style | https://go.dev/LICENSE |
| Alpine Linux packages | Alpine 3.20 runtime repositories | Individual package licenses | https://pkgs.alpinelinux.org/packages?branch=v3.20 |

The image includes upstream AWG and QR license texts under
`/usr/share/licenses/awg-panel/`, and the exact AmneziaWG Tools source archive
under `/usr/share/awg-panel/amneziawg-tools-source.tar.gz`. Redistributors must
retain notices and satisfy the licenses of all included components, including
Alpine packages and upstream Go module dependencies. This notice is not a
replacement for those terms and does not grant a license to legacy source files.

## Protocol references

- Official config parser: https://github.com/amnezia-vpn/amneziawg-tools/blob/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843/src/config.c
- Official control protocol: https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/uapi.go
- Official share-link codec: https://github.com/amnezia-vpn/config-decoder/blob/master/mainwindow.cpp
- AmneziaVPN client: https://github.com/amnezia-vpn/amnezia-client
- Official AWG JSON model: https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/core/models/protocols/awgProtocolConfig.cpp

The official link codec uses Qt qCompress: a four-byte big-endian uncompressed
length followed by zlib, encoded as URL-safe base64 without trailing padding.
