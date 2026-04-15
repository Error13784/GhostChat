# GhostChat - Secure P2P Chat over Tor & I2P

GhostChat is a terminal-based P2P chat application that uses Tor Onion Services for anonymity and GPG for end-to-end encryption. It allows you to chat with friends securely without relying on central servers.

## Features
- **Anonymous:** Uses Tor Onion Services (Hidden Services) or I2P to hide your IP address.
- **Secure:** End-to-End Encrypted using GPG (RSA 2048-bit).
- **P2P:** Direct connection to your friend's onion or i2p address.
- **Friend Management:** Whitelist-based friend system using GPG keys.
- **Image Sharing:** Send and receive images securely.
- **Groupchats:** Create, manage, and delete private group conversations.
- **Persistent Sessions:** "Enter" a chat or group to talk naturally without repeating commands.
- **Local Discovery:** Scan your local network (WiFi) to find other GhostChat users.
- **Network Agnostic:** Switch between Tor, I2P, or use both simultaneously.

## 🚀 What's New in V1.3 (Major Update)
- **Persistent Chat Sessions:** No more typing `/chat` for every message! Enter a "room" with `/chat <name>` or `/gc_chat <name>` and talk freely. Use `/goback` to exit.
- **Full Groupchat Suite:** Create (`/gc_create`), Chat (`/gc_chat`), Kick members (`/gc_kick`), and Delete groups (`/gc_delete`).
- **I2P & Multi-Network Support:** Switch between Tor and I2P or use `both` for maximum delivery reliability.
- **Local Network Discovery:** Use `/scan` to find peers on your current WiFi for "nearby" chatting without sharing onion addresses first.
- **Image Sharing:** Send images with `/sendimg`. Received images are automatically saved and opened.
- **Redesigned UI:** A beautiful, categorized `/help` menu and customizable terminal colors via `/colors`.
- **Better Navigation:** Full arrow-key support for command editing and a `/clear` command to keep your terminal tidy.
- **Termux Optimization:** Improved bootstrap logic with a 10-minute timeout to ensure stable connections on mobile data.

## Prerequisites

1. **Python 3.x**
2. **Tor:** `pkg install tor` (Termux) or `sudo apt install tor` (Linux).
3. **GnuPG:** `pkg install gnupg` (Termux) or `sudo apt install gnupg` (Linux).
4. **I2P (Optional):** Requires `i2pd` running for I2P features.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

1. **Start:** `python ghostchat.py`
2. **Identify:** `/myinfo` shows your address. Share the `my_key.asc` file with friends.
3. **Connect:** `/add <name> <address> <key_path>`
4. **Chat:** `/chat <name>` or `/gc_chat <group_name>` to enter a session.
5. **Exit Session:** `/goback` or `/exit` returns you to the main menu.
6. **Discover:** `/scan` to find users on your local WiFi.

## ⚠️ Important Note on Key Management
For better security and to avoid GPG import conflicts, **DO NOT** store your friends' `.asc` key files inside the `GhostChat` main directory or the `ghostchat_data` folder. 

Keep them in a separate folder (e.g., `~/Downloads/keys/`) and provide the full path when using the `/add` command.

---
*Fed's won't find us here.*
