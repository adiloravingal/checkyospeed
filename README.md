# checkyospeed

A terminal network monitor for macOS. See which apps, sites and **browser tabs** are eating your bandwidth, and whether a slow download is **your network's fault or the server's**.

```
 checkyospeed   ↓ 21.3 Mb/s  ↑ 0.6 Kb/s   ping 18/24ms   line: ok
 test 14:03  ↓ 94.2 Mb/s  ↑ 31.0 Mb/s  rpm 820
 diag remote/server: line healthy, 23% used — Brave ← omarchy.org limited by destination
                                                    ▃▄▄▅▆█▇▆▅▆ peak 24.9 Mb/s
  APP                          ↓            ↑  share
 ────────────────────────────────────────────────────────────────
▌ Brave                    21.3 Mb/s     0.6 Kb/s  ████████████████
  └ omarchy.org            21.3 Mb/s     0.6 Kb/s  ▸ Omarchy - Beautiful, fun & agentic Linux
  Claude                    0.3 Kb/s       0 Kb/s  ░░░░░░░░░░░░░░░░
  └ anthropic               0.3 Kb/s       0 Kb/s
 ── local ──
  netbiosd                  0.8 Kb/s     0.5 Kb/s  ████████████████
 [t] test [/] filter [j/k] move [l/h] expand [q] quit   via WARP
```

## Install

```sh
brew install adiloravingal/tap/checkyospeed
```

or with Go:

```sh
go install github.com/adiloravingal/checkyospeed@latest
```

macOS only (uses `nettop`, `networkQuality` and AppleScript, which ship with macOS).

## What it shows

- **Live ↓/↑ totals** and a 60-second download sparkline. VPN/tunnel processes (Cloudflare WARP, WireGuard, …) are excluded so traffic isn't double-counted.
- **Per-app table** with helpers folded into their parent ("Brave Browser Helper" → Brave). LAN chatter (AirDrop, mDNS, Jellyfin, …) is listed separately under `── local ──`.
- **Destinations per app** as a tree, named from your open browser tabs, reverse DNS, TLS certificate names (so ISP-hosted YouTube/Netflix caches show as the real service), or known provider IP ranges (google, cloudflare, aws, meta, …).
- **Tab titles** for Brave, Chrome, Edge, Arc and Safari. Browsers route all tabs through one network process, so tabs are matched by the sites they're on. That makes it a best guess, not exact per-tab accounting.
- **Ping**, idle vs under load. A red ▲ means latency triples under load (bufferbloat).
- **Line quality**: `rough` when retransmits and out-of-order packets spike.
- **`diag`**, which works out whether a slow download is caused by:
  - **your network**: line saturated (≥80% of tested speed), packet loss, or bufferbloat
  - **the remote server**: your line is healthy and mostly idle, but the download is still slow

  Press `t` once so it knows your line's capacity.

## Keys

| key | action |
| --- | --- |
| `t` | run Apple's `networkQuality` speed test (~20 s) |
| `/` | filter by app, site or tab title (`esc` clears) |
| `j` / `k` | move |
| `l` / `h` / `enter` | expand / collapse an app's destinations |
| `q` | quit |

## Permissions & privacy

- On first run macOS asks to let your terminal control your browser. That's how tab titles are read. If you decline, everything else still works.
- Nothing is uploaded. The only traffic it creates is:
  - a ping to `1.1.1.1` every 2 s
  - Apple's speed-test servers when you press `t`
  - one TLS handshake (no data sent) to each new server your apps are already talking to, to read the certificate name. This turns ISP-hosted caches like `segment-119-227.sify.net` into `googlevideo.com`.

## Build

```sh
go build -o checkyospeed .
./checkyospeed
```

## License

MIT
