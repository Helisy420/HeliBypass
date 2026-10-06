# Third-party software and assets

HeliBypass is MIT-licensed (see `LICENSE`). It builds on, and ships parts of, the projects below.
Full license texts are in `assets/licenses/`.

## Projects this app is based on

| Project | Used for | License |
|---|---|---|
| [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) | The Telegram proxy (`heli-tgproxy`) is a Rust port of it, including its Cloudflare domain-list format | MIT, `assets/licenses/tg-ws-proxy.txt` |
| [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) | Strategy `.bat` files, filter lists, test targets and service logic (`assets/zapret/`, `heli-zapret`) | MIT, `assets/licenses/zapret-discord-youtube.txt` |
| [bol-van/zapret](https://github.com/bol-van/zapret) | `winws.exe` and the payload `.bin` files in `assets/zapret/bin/` (unmodified) | MIT, `assets/licenses/zapret.txt` |
| [basil00/WinDivert](https://github.com/basil00/WinDivert) | `WinDivert.dll` and the signed `WinDivert64.sys` driver in `assets/zapret/bin/` (unmodified) | LGPL-3.0 or GPL-2.0 (your choice), `assets/licenses/WinDivert.txt` |
| [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers) | The suite of hosts for the "DPI checkers" test, downloaded at run time | Apache-2.0 |

`winws.exe`, `WinDivert.dll`, `WinDivert64.sys` and `cygwin1.dll` are the upstream binaries from
zapret-discord-youtube 1.10.3, redistributed as-is. WinDivert's source is at
<https://github.com/basil00/WinDivert>; the driver is Microsoft-signed and must not be modified.
Verify them against the upstream release before distributing builds.

## Fonts and icons

| Asset | License |
|---|---|
| Montserrat (`assets/fonts/`) | SIL OFL 1.1, `assets/licenses/montserrat-OFL.txt` |
| JetBrains Mono (`assets/fonts/`) | SIL OFL 1.1, `assets/licenses/jetbrains-mono-OFL.txt` |
| [Lucide](https://lucide.dev) icons (`assets/icons/`) | ISC, `assets/licenses/lucide.txt` |

## Libraries

Rust dependencies are listed in `Cargo.lock`; the notable ones are
[Slint](https://slint.dev) (UI; used under its royalty-free desktop license, which asks for
attribution), tokio, rustls, h2, the RustCrypto crates, and tray-icon. Check each crate's license
(`cargo install cargo-about` can generate a full report) before distributing binaries.
