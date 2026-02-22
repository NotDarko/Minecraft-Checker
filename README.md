# Minecraft Account Checker  
**Made By Darko (@3_1o)**

---

## Overview

A tool for checking Microsoft/Xbox Game Pass accounts and checking Minecraft account features.  
This utility is intended for security testing, data enrichment, and Minecraft-related account capture—not for unauthorized access or illegal activities.

**Key Features:**
- Fast, multi-threaded checking of email:password combos
- Supports HTTP, SOCKS4/5 proxies, and proxyless checking
- Captures full account info: UUID, username, account type, cape status, Hypixel stats, name change eligibility, email access, bans, and more
- Discord webhook notifications with detailed information
- Modular config: control captures and notifications
- Auto-creation of results directory and config file

---

## Setup

### Dependencies

You'll need **Python 3.8+** and the following recommended setup:

1. **Clone or download this repository.**

2. **Install all required dependencies via requirements.txt**  
   Run the following command in your project folder:
   ```bash
   pip install -r requirements.txt
   ```
   This will automatically install the correct versions of:
   - `colorama`
   - `requests` (with SOCKS support)
   - `urllib3`
   - `configparser`
   - `PySocks`
   - The [pyCraft](https://github.com/ammaraskar/pyCraft) Minecraft networking library (installed directly from GitHub)

**Note:**  
- `requests[socks]` and `PySocks` are required for SOCKS proxy support.
- The Minecraft protocol library is installed via the following line in `requirements.txt`:  
  ```
  git+https://github.com/ammaraskar/pyCraft.git
  ```
- You do **not** need to manually install modules like `python-socks` or `http.cookiejar` unless prompted by an error.
- There is no need to install `minecraft-protocol` or the older `minecraft` libraries; all relevant Minecraft features use `pyCraft` as specified.

---

If you have any install problems or a missing dependency error, try updating `pip` and `setuptools`:
```bash
pip install --upgrade pip setuptools
```

---

## Configuration

Upon first run, a file named `config.ini` is created automatically.  
**Default webhook message includes all captured details.**  
Modify settings in `config.ini` as needed for proxies, webhooks, and capture preferences.

**Webhook Message Template (customizable in config file):**
```
New Hit!
Email: <email>
Password: <password>
Username: <n>
UUID: <uuid>
Account Type: <type>
Capes: <capes>

--- Hypixel Stats ---
Rank: <hypixel>
Level: <level>
First Login: <firstlogin>
Last Login: <lastlogin>
Bedwars Stars: <bedwarsstars>
Skyblock Networth: <skyblockcoins>

--- Account Info ---
OptiFine Cape: <ofcape>
Email Access: <access>
Can Change Name: <namechange>
Last Name Change: <lastchanged>
Hypixel Ban Status: <banned>
```

## Placeholder meanings

Use these placeholders in your output format. They will automatically be replaced with the account’s info.

- `<email>` - Account email
- `<password>` - Account password
- `<n>` - Username / IGN
- `<uuid>` - Minecraft UUID
- `<type>` - Account type (Normal Minecraft, Game Pass, etc.)
- `<capes>` - Capes detected (Minecon, Migrator, etc.)

### Hypixel placeholders
- `<hypixel>` - Hypixel rank (VIP, MVP+, etc.)
- `<level>` - Hypixel network level
- `<firstlogin>` - Hypixel first login date/time
- `<lastlogin>` - Hypixel last login date/time
- `<bedwarsstars>` - BedWars stars
- `<skyblockcoins>` - SkyBlock coins/purse amount

### Extra placeholders
- `<ofcape>` - OptiFine cape status (Yes / No / N/A)
- `<namechange>` - Can change username (Yes / No / N/A)
- `<lastchanged>` - Last name change date/time
- `<banned>` - Banned status (ban / unbanned / unknown)


---

## Usage

1. **Place combos**
   - Add `email:password` combos to `combos.txt` (one per line).

2. **Place proxies**
   - For HTTP/SOCKS4/SOCKS5, add proxies to `proxies.txt` (one per line, e.g. `ip:port` or `user:pass@ip:port`).

3. **Run**
   ```bash
   python mc.py
   ```
   - The script will prompt for the number of threads (e.g. 100).
   - Choose proxy mode (HTTP, SOCKS4, SOCKS5, or proxyless).
   - Checking will begin.
   - Live statistics are shown in the console.

4. **Results**
   - Hits, captures, and other files are saved to the `results/` directory.

---

## Folder Structure

- `combos.txt` — your email:password combos
- `proxies.txt` — proxies list (if using)
- `mc.py` — main file (checker)
- `ban_proxies.txt` — optional, for Hypixel ban checks via proxy
- `config.ini` — application config (auto-generated)
- `results/`
  - `hits.txt` — successful accounts
  - `captures.txt` — full account captures
  - `banned.txt` — banned accounts
  - `unbanned.txt` — unbanned accounts
  - `game_pass.txt`, `game_pass_ultimate.txt`, `normal_minecraft.txt` — by type

---

## Notes & Disclaimer

- **For educational/ethical use only.** Do not use on accounts you do not own or have explicit permission to test.
- Proxyless mode may result in higher error or rate limit.
- Some features may change if endpoint responses or Minecraft APIs change.
- Pull requests and improvements are welcome.

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