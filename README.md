# GhostChat - Secure P2P Chat over Tor

GhostChat is a terminal-based P2P chat application that uses Tor Onion Services for anonymity and GPG for end-to-end encryption. It allows you to chat with friends securely without relying on central servers.

## Features
- **Anonymous:** Uses Tor Onion Services (Hidden Services) to hide your IP address.
- **Secure:** End-to-End Encrypted using GPG.
- **P2P:** Direct connection to your friend's onion address.
- **Friend Management:** Whitelist-based friend system using GPG keys.

## Prerequisites

1. **Python 3.x**
2. **Tor:** You must have the `tor` executable installed on your system.
   - Debian/Ubuntu: `sudo apt install tor`
   - macOS: `brew install tor`
   - Termux (Android): `pkg install tor`
3. **GnuPG:** Ensure `gpg` is installed.
   - Termux (Android): `pkg install gnupg`

## Installation

### Desktop (Linux/macOS)
1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Termux (Android)
1. Install system packages:
   ```bash
   pkg update
   pkg install python tor gnupg
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Setup storage to import keys from your phone:
   ```bash
   termux-setup-storage
   ```
   *Your phone's downloads will then be accessible at `~/storage/downloads/`.*

## Usage

1. Start the chat:
   ```bash
   python ghostchat.py
   ```
   *Note: The first time you run it, it will take a minute to launch Tor and generate a GPG key.*

2. **Get your info:**
   Type `/myinfo` to see your Onion Address and GPG Fingerprint. A `my_key.asc` file will be created. Share this file and your onion address with your friend securely.

3. **Add a friend:**
   Get your friend's Onion Address and their Public Key file (e.g., `friend_key.asc`).
   ```
   /add <friend_name> <friend_onion_address> <path_to_key_file>
   ```
   Example:
   ```
   /add alice 2g7...xyz.onion alice_key.asc
   ```

4. **Chat:**
   ```
   /chat <friend_name> Hello secure world!
   ```

## Troubleshooting

- **Tor startup failed:** Ensure `tor` is in your system PATH. If it's in `/usr/sbin/`, add it to your PATH or symlink it.
- **Connection failed:** Tor connections can be slow. Ensure your friend is online and their GhostChat is running. Initial connections can take up to a minute.
