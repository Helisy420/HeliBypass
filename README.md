# HeliBypass

One Windows app for two jobs that used to need two tools:

- **Telegram proxy**: a local MTProto proxy that carries Telegram over WebSocket
  (a Rust port of [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)).
- **DPI bypass** for Discord, YouTube and others, driving zapret's `winws.exe`
  (replaces the batch and PowerShell scripts of
  [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)).

Written in Rust with a small native UI (Slint, software renderer): no webview, no Python, and a
small memory footprint (tens of MB). English and Russian.

## Features

- Telegram proxy with a direct, domain-fronted and Cloudflare route, Fake-TLS, connection pool,
  live traffic stats and an optional speed limit. Imports an existing tg-ws-proxy configuration on
  first run, so Telegram keeps the same secret.
- All 22 upstream strategies, parsed from their `.bat` files (your own `.bat` files can be added),
  with game filter and IPSet modes.
- Strategy tests (HTTP / TLS 1.2 / TLS 1.3 per service, plus the "DPI checkers" suite) that rank
  strategies on your own connection, and a strategy builder.
- Windows service install/remove, diagnostics with one-click fixes, hosts-file and IPSet updates.
- Tray popup, launch at login, single instance.

## Layout

| Crate | Purpose |
|---|---|
| `crates/heli-core` | Paths, config, TLS, a small HTTPS client, activity feed, elevation helpers |
| `crates/heli-tgproxy` | The MTProto-over-WebSocket proxy |
| `crates/heli-zapret` | Strategies, engine supervision, service, diagnostics, tests, lists |
| `crates/heli-app` | The UI (`ui/*.slint`), tray, translations (`lang/`), glue |

`winws.exe` and the WinDivert driver are bundled unmodified in `assets/zapret/bin/` and embedded
into the executable. Their SHA-256 is verified against the embedded copy before every launch.

## Build

Requirements: Windows 10/11, a recent stable Rust toolchain and the MSVC build tools.

```bash
cargo build --release -p heli-bypass
```

The executable is `target/release/heli-bypass.exe`.

```bash
cargo test --workspace                              # unit and integration tests
cargo test -p heli-tgproxy --test live_telegram -- --ignored   # needs access to Telegram
```

## Running

The Telegram proxy works without administrator rights. The bypass needs them (WinDivert); the app
shows a banner with a "Restart as administrator" button, and "Launch at login" uses a scheduled
task with the highest privileges so there is no prompt at every sign-in.

Data (config, lists, logs) lives in `%ProgramData%\HeliBypass`, or in the folder named by the
`HELIBYPASS_HOME` environment variable.

## Notes

- The bypass has not been verified on every ISP; use *Run tests* to pick a strategy for yours.
- The HTTP/2 media accelerator for the Telegram proxy is experimental and off by default.
- Editing the hosts file, installing a Windows service and loading the WinDivert kernel driver are
  real changes to your system. Read what each button does before using it.

## License

MIT, see [LICENSE](LICENSE). Bundled third-party software and assets keep their own licenses, see
[THIRD_PARTY.md](THIRD_PARTY.md).
