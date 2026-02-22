# Minecraft Account Checker

**Author:** NotDarko (original: @3_1o)

---

## Overview

A multi-threaded checker that attempts Microsoft/Xbox login for email:password combos and enriches valid Minecraft accounts with profile and service data.

Implemented features:
- Microsoft/Xbox authentication to obtain a Minecraft access token
- Entitlements check to determine account ownership type (Normal Minecraft / Game Pass / Game Pass Ultimate)
- Minecraft profile fetch (username, UUID, capes)
- Optional Hypixel stats scraping and SkyBlock networth lookup (EliteBot API)
- Hypixel ban check via a pyCraft connection attempt
- OptiFine cape check
- Name-change eligibility check via Minecraft profile namechange endpoint
- Discord webhook notifications (embed or plain content)
- Proxy support: HTTP, SOCKS4, SOCKS5, or proxyless
- Results saved to a timestamped session folder under `results/`

---

## Requirements

- Python 3.8+
- Third-party packages used by the code:
  - `requests` (use `requests[socks]` if using SOCKS proxies)
  - `PySocks` (`socks`)
  - `colorama`
  - `urllib3`
  - `pyCraft` (the code imports `minecraft.networking.*` — if missing, install from https://github.com/ammaraskar/pyCraft.git)

The script also uses standard library modules such as `configparser`, `threading`, `concurrent.futures`, `dataclasses`, `uuid`, `socket`, `json`, `time`, `datetime`, `urllib.parse`, `warnings`, and `http.cookiejar`.

---

## Configuration

On first run the script will create a `config.ini`. The code reads the following keys:

[Settings]
- `webhook` — Discord webhook URL to send hits to (if empty, no webhook is sent)
- `embed` — True/False: whether to use Discord embed payloads
- `max_retries` — integer: retry attempts for web requests during authentication
- `webhook_message` — custom message template used when building webhook content (placeholders listed below)

[Captures]
- `hypixel_stats` — True/False: fetch Hypixel stats and attempt SkyBlock networth
- `optifine_cape` — True/False: check for OptiFine cape
- `name_change_info` — True/False: check name-change eligibility/date
- `ban_check` — True/False: run Hypixel ban check using pyCraft

Only the keys listed above are read by `mc.py`. Other keys that may appear in example configs or previous versions are not used by the current code and have been omitted here.

---

## Webhook placeholders

The webhook message template (`webhook_message`) and the embed builder replace these placeholders:

- `<email>`
- `<password>`
- `<n>` (username / IGN)
- `<uuid>`
- `<type>` (account type determined from entitlements)
- `<capes>`
- `<hypixel>`
- `<level>`
- `<firstlogin>`
- `<lastlogin>`
- `<bedwarsstars>`
- `<skyblockcoins>`
- `<ofcape>`
- `<namechange>`
- `<lastchanged>`
- `<banned>`

---

## Usage

1. Put combos in `combos.txt` (one `email:password` per line).

2. (Optional) Put proxies in `proxies.txt` (one per line). For Hypixel ban checks you can provide `ban_proxies.txt` (one per line).

3. Run:
   ```bash
   python mc.py
   ```
   - Enter the number of threads when prompted.
   - Choose proxy type (HTTP, SOCKS4, SOCKS5, or Proxyless).

4. Results are saved to a session folder under `results/session_YYYY-MM-DD_HH-MM-SS/`. Files include:
   - `hits.txt`
   - `captures.txt`
   - `banned.txt`
   - `unbanned.txt`
   - `game_pass.txt`, `game_pass_ultimate.txt`, `normal_minecraft.txt` (depending on account type)

Live console statistics (CPM, hits, invalids, 2FA, etc.) are displayed while the checker runs.

---

## Notes & Disclaimer

- This project is provided for educational and ethical purposes only. It is NOT intended to be used for illegal activity or unauthorized access.
- Use this tool only on accounts you own or for which you have explicit permission to test. Unauthorized use may be illegal and is strictly prohibited.
- The code disables SSL verification on many requests (`verify=False`) and suppresses urllib3 warnings; this is how the script is written.
- Hypixel ban checks and external API calls (EliteBot) are best-effort and may fail depending on network conditions or changes to external services.

---

## Troubleshooting

- If the script fails to run, ensure all dependencies are installed, Python is up to date, and the required files exist.
- For issues with proxies, check format and firewall restrictions.
- For Discord webhook problems, confirm your server permissions and webhook URL.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Author

NotDarko  
GitHub: [NotDarko](https://github.com/NotDarko)
