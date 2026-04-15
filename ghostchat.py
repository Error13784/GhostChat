import os
import sys
import time
import socket
import threading
import json
import shutil
import base64
import tempfile
import subprocess
try:
    import readline
except ImportError:
    pass # Readline not available on some platforms
import socks  # pysocks
from stem.control import Controller
from stem.process import launch_tor_with_config
import gnupg
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Configuration
DATA_DIR = os.path.join(os.getcwd(), "ghostchat_data")
TOR_DIR = os.path.join(DATA_DIR, "tor")
GPG_DIR = os.path.join(DATA_DIR, "gpg")
FRIENDS_FILE = os.path.join(DATA_DIR, "friends.json")
GROUPS_FILE = os.path.join(DATA_DIR, "groups.json")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
I2P_SOCKS_PORT = 4447
APP_PORT = 13337  # Local port for the app to listen on
ONION_PORT = 80   # Port exposed on the onion address
DISCOVERY_PORT = 13338 # UDP Port for local scanning

# Ensure directories exist
os.makedirs(TOR_DIR, exist_ok=True)
os.makedirs(GPG_DIR, exist_ok=True)
os.chmod(GPG_DIR, 0o700)

class GhostChat:
    def __init__(self):
        self.gpg = gnupg.GPG(gnupghome=GPG_DIR)
        self.tor_process = None
        self.controller = None
        self.onion_address = None
        self.friends = self.load_friends()
        self.groups = self.load_groups()
        self.config = self.load_config()
        self.my_fingerprint = None
        self.current_chat = None
        self.current_group = None
        self.nearby_peers = {} # For /scan
        
        # Setup colors
        self._set_colors()
        
        # Setup GPG
        self.setup_gpg()

    def _set_colors(self):
        self.colors = {
            "prompt": self.config.get("colors", {}).get("prompt", Fore.BLUE),
            "msg_sender": self.config.get("colors", {}).get("msg_sender", Fore.MAGENTA),
            "msg_text": self.config.get("colors", {}).get("msg_text", Fore.WHITE),
            "info": self.config.get("colors", {}).get("info", Fore.CYAN),
            "success": self.config.get("colors", {}).get("success", Fore.GREEN),
            "warn": self.config.get("colors", {}).get("warn", Fore.YELLOW),
            "error": self.config.get("colors", {}).get("error", Fore.RED),
        }

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {"username": "Ghost", "colors": {}, "network": "tor"}

    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)

    def load_friends(self):
        if os.path.exists(FRIENDS_FILE):
            with open(FRIENDS_FILE, 'r') as f:
                return json.load(f)
        return {}

    def save_friends(self):
        with open(FRIENDS_FILE, 'w') as f:
            json.dump(self.friends, f, indent=4)

    def load_groups(self):
        if os.path.exists(GROUPS_FILE):
            with open(GROUPS_FILE, 'r') as f:
                return json.load(f)
        return {}

    def save_groups(self):
        with open(GROUPS_FILE, 'w') as f:
            json.dump(self.groups, f, indent=4)

    def play_notification(self):
        print("\a", end="", flush=True) # Bell character
        try:
            if sys.platform == "linux":
                if shutil.which("paplay"):
                    subprocess.Popen(["paplay", "/usr/share/sounds/freedesktop/stereo/message.oga"], stderr=subprocess.DEVNULL)
                elif shutil.which("aplay"):
                    pass
        except:
            pass

    def start_discovery(self):
        def _discovery_loop():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                s.bind(('', DISCOVERY_PORT))
            except:
                return 
            while True:
                data, addr = s.recvfrom(1024)
                try:
                    payload = json.loads(data.decode())
                    if payload.get('type') == 'ghost_hello':
                        peer_info = {
                            'name': payload.get('u'),
                            'onion': payload.get('o'),
                            'last_seen': time.time()
                        }
                        self.nearby_peers[addr[0]] = peer_info
                    elif payload.get('type') == 'ghost_ping':
                        self._broadcast_presence()
                except:
                    pass

        threading.Thread(target=_discovery_loop, daemon=True).start()
        def _heartbeat():
            while True:
                self._broadcast_presence()
                time.sleep(60)
        threading.Thread(target=_heartbeat, daemon=True).start()

    def _broadcast_presence(self):
        if not self.onion_address: return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            msg = json.dumps({
                'type': 'ghost_hello',
                'u': self.config.get('username', 'Ghost'),
                'o': self.onion_address
            })
            s.sendto(msg.encode(), ('<broadcast>', DISCOVERY_PORT))
            s.close()
        except:
            pass

    def scan_area(self):
        print(f"{self.colors['warn']}[*] Scanning local network for GhostChat peers...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            msg = json.dumps({'type': 'ghost_ping'})
            s.sendto(msg.encode(), ('<broadcast>', DISCOVERY_PORT))
            s.close()
        except:
            pass
        
        time.sleep(2) 
        if not self.nearby_peers:
            print(f"{self.colors['error']}[!] No local peers found.")
        else:
            print(f"{self.colors['info']}Local Peers Found:")
            for ip, info in self.nearby_peers.items():
                print(f"  - {info['name']} at {info['onion']} (IP: {ip})")

    def _handle_client(self, conn):
        try:
            data = b""
            while True:
                chunk = conn.recv(16384)
                if not chunk:
                    break
                data += chunk
            
            if not data:
                return

            decrypted = self.gpg.decrypt(data.decode('utf-8', errors='ignore'))
            
            if decrypted.ok:
                self.play_notification()
                try:
                    payload = json.loads(decrypted.data.decode())
                    msg_text = payload.get('m', '')
                    sender_defined_username = payload.get('u', 'Ghost')
                    image_data = payload.get('i', None)
                    group_id = payload.get('g', None)
                except:
                    msg_text = decrypted.data.decode()
                    sender_defined_username = "Unknown"
                    image_data = None
                    group_id = None

                sender_name = "Unknown"
                if decrypted.fingerprint:
                    for name, f_data in self.friends.items():
                        if f_data['fingerprint'] == decrypted.fingerprint:
                            sender_name = name
                            break
                    if sender_name == "Unknown":
                        sender_name = f"ID:{decrypted.fingerprint[-8:]}"

                prefix = ""
                if group_id:
                    prefix = f"{Fore.YELLOW}[Group: {group_id}] "
                
                display_name = f"{sender_name} ({sender_defined_username})" if sender_name != sender_defined_username else sender_name
                print(f"\n{prefix}{self.colors['msg_sender']}[{display_name}] {self.colors['msg_text']}{msg_text}")
                
                if image_data:
                    try:
                        img_bytes = base64.b64decode(image_data)
                        fd, path = tempfile.mkstemp(suffix=".png")
                        with os.fdopen(fd, 'wb') as tmp:
                            tmp.write(img_bytes)
                        print(f"{self.colors['success']}[+] Received an image! Saved to: {path}")
                        if shutil.which("xdg-open"):
                            subprocess.Popen(["xdg-open", path], stderr=subprocess.DEVNULL)
                    except Exception as ie:
                        print(f"{self.colors['error']}[!] Failed to decode image: {ie}")

                prompt_prefix = ""
                if self.current_group:
                    prompt_prefix = f"{Fore.YELLOW}[Group: {self.current_group}] "
                elif self.current_chat:
                    prompt_prefix = f"{Fore.GREEN}[Chat: {self.current_chat}] "
                print(f"{prompt_prefix}{self.colors['prompt']}ghostchat> {Style.RESET_ALL}", end="", flush=True)
            else:
                pass

        except Exception as e:
            pass
        finally:
            conn.close()

    def send_message(self, target, msg, image_path=None, group_id=None):
        targets = []
        if group_id:
            if group_id in self.groups:
                for member_name in self.groups[group_id]['members']:
                    if member_name in self.friends:
                        f_info = self.friends[member_name].copy()
                        f_info['name'] = member_name
                        targets.append(f_info)
            else:
                print(f"{self.colors['error']}[!] Group '{group_id}' not found.")
                return
        elif target in self.friends:
            f_info = self.friends[target].copy()
            f_info['name'] = target
            targets.append(f_info)
        elif target:
            targets.append({'onion': target, 'fingerprint': None, 'name': target})
        else:
            return

        image_b64 = None
        if image_path and os.path.exists(image_path):
            with open(image_path, "rb") as image_file:
                image_b64 = base64.b64encode(image_file.read()).decode('utf-8')

        net_mode = self.config.get('network', 'tor')

        for friend_data in targets:
            onion = friend_data['onion']
            fingerprint = friend_data.get('fingerprint')
            name = friend_data.get('name', onion)

            if not fingerprint:
                for f_name, f_data in self.friends.items():
                    if f_data['onion'] == onion:
                        fingerprint = f_data['fingerprint']
                        break
            
            if not fingerprint:
                print(f"{self.colors['error']}[!] No key found for {name}. Add them as a friend first.")
                continue

            payload = json.dumps({
                "u": self.config.get("username", "Ghost"),
                "m": msg,
                "i": image_b64,
                "g": group_id
            })

            encrypted = self.gpg.encrypt(payload, fingerprint, sign=self.my_fingerprint, always_trust=True)
            if not encrypted.ok:
                print(f"{self.colors['error']}[!] Encryption failed for {name}: {encrypted.status}")
                continue

            success = False
            def _try_send(port, label):
                try:
                    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", port)
                    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(30)
                    s.connect((onion, ONION_PORT))
                    s.sendall(str(encrypted).encode('utf-8'))
                    s.close()
                    print(f"{self.colors['success']}[+] Sent to {name} via {label}!")
                    return True
                except:
                    return False

            if net_mode in ['tor', 'both']:
                if _try_send(TOR_SOCKS_PORT, "Tor"):
                    success = True
            
            if not success and net_mode in ['i2p', 'both']:
                if _try_send(I2P_SOCKS_PORT, "I2P"):
                    success = True

            if not success:
                print(f"{self.colors['error']}[!] Failed to send to {name}")

    def setup_gpg(self):
        keys = self.gpg.list_keys(secret=True)
        if not keys:
            print(f"{self.colors['warn']}[*] Generating new GPG keypair for GhostChat... This may take a moment.")
            input_data = self.gpg.gen_key_input(
                key_type="RSA",
                key_length=2048,
                name_real="GhostChat User",
                name_email="ghost@chat.local",
                no_protection=True
            )
            key = self.gpg.gen_key(input_data)
            self.my_fingerprint = key.fingerprint
            print(f"{self.colors['success']}[+] Key generated: {self.my_fingerprint}")
        else:
            self.my_fingerprint = keys[0]['fingerprint']
            print(f"{self.colors['success']}[+] Loaded existing key: {self.my_fingerprint}")

    def _find_tor_executable(self):
        tor_path = shutil.which("tor")
        if tor_path:
            return tor_path
        common_paths = [
            "/usr/sbin/tor", 
            "/usr/local/bin/tor", 
            "/opt/homebrew/bin/tor",
            "/data/data/com.termux/files/usr/bin/tor"
        ]
        for path in common_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        return None

    def start_tor(self):
        print(f"{self.colors['warn']}[*] Launching Tor... (This can take a minute)")
        tor_cmd = self._find_tor_executable()
        if not tor_cmd:
            print(f"{self.colors['error']}[!] 'tor' executable not found.")
            sys.exit(1)

        try:
            self.tor_process = launch_tor_with_config(
                config={
                    'SocksPort': str(TOR_SOCKS_PORT),
                    'ControlPort': str(TOR_CONTROL_PORT),
                    'DataDirectory': TOR_DIR,
                    'HiddenServiceDir': os.path.join(TOR_DIR, 'hs'),
                    'HiddenServicePort': f'{ONION_PORT} 127.0.0.1:{APP_PORT}',
                },
                tor_cmd=tor_cmd,
                take_ownership=True,
                timeout=600, # 10 minute timeout for Termux
                init_msg_handler=lambda line: print(f"{Fore.CYAN}[Tor] {line}") if "Bootstrapped" in line else None,
            )
        except Exception as e:
            print(f"{self.colors['error']}[!] Failed to launch Tor: {e}")
            sys.exit(1)

        try:
            self.controller = Controller.from_port(port=TOR_CONTROL_PORT)
            self.controller.authenticate()
            hs_dir = os.path.join(TOR_DIR, 'hs', 'hostname')
            while not os.path.exists(hs_dir):
                time.sleep(1)
            with open(hs_dir, 'r') as f:
                self.onion_address = f.read().strip()
            print(f"{self.colors['success']}[+] Tor Ready!")
            print(f"{self.colors['success']}[+] My Onion Address: {Fore.WHITE}{self.onion_address}")
            self.original_socket = socket.socket
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", TOR_SOCKS_PORT)
            socket.socket = socks.socksocket
        except Exception as e:
            print(f"{self.colors['error']}[!] Error connecting to Tor controller: {e}")
            self.stop()
            sys.exit(1)

    def start_listener(self):
        server_thread = threading.Thread(target=self._listen_loop, daemon=True)
        server_thread.start()

    def _listen_loop(self):
        while not hasattr(self, 'original_socket'):
            time.sleep(0.5)
        s = self.original_socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', APP_PORT))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def import_key(self, path):
        if not os.path.exists(path):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            alt_path = os.path.join(script_dir, path)
            if os.path.exists(alt_path):
                path = alt_path
            else:
                return None
        with open(path, 'r') as f:
            key_data = f.read()
        import_result = self.gpg.import_keys(key_data)
        if import_result.fingerprints:
            return import_result.fingerprints[0]
        scan = self.gpg.scan_keys(key_data)
        return scan[0]['fingerprint'] if scan else None

    def show_help(self):
        c1, c2, reset = Fore.CYAN, Fore.WHITE, Style.RESET_ALL
        print(f"\n{self.colors['info']}┌──────────────────────────────────────────────────────────┐")
        print(f"{self.colors['info']}│ {Style.BRIGHT}GHOSTCHAT COMMANDS{Style.NORMAL}                                       │")
        print(f"{self.colors['info']}├──────────────────────────────────────────────────────────┤")
        print(f"{self.colors['info']}│ {Style.BRIGHT}ACCOUNT & NETWORK{Style.NORMAL}                                        │")
        print(f"{self.colors['info']}│  {c1}/myinfo{c2}           - Show your onion address and GPG key  │")
        print(f"{self.colors['info']}│  {c1}/setname <name>{c2}   - Change your display username         │")
        print(f"{self.colors['info']}│  {c1}/network <mode>{c2}   - Switch network (tor, i2p, both)      │")
        print(f"{self.colors['info']}│  {c1}/colors{c2}           - Customize your chat colors           │")
        print(f"{self.colors['info']}│  {c1}/clear{c2}            - Clear the terminal screen            │")
        print(f"{self.colors['info']}│  {c1}/quit{c2}             - Exit GhostChat                       │")
        print(f"{self.colors['info']}│                                                          │")
        print(f"{self.colors['info']}│ {Style.BRIGHT}SOCIAL & DISCOVERY{Style.NORMAL}                                      │")
        print(f"{self.colors['info']}│  {c1}/add <n> <o> <k>{c2}  - Add friend (name, onion, key file)    │")
        print(f"{self.colors['info']}│  {c1}/remove <name>{c2}    - Remove a friend from your list       │")
        print(f"{self.colors['info']}│  {c1}/list{c2}             - Show all friends and groups          │")
        print(f"{self.colors['info']}│  {c1}/scan{c2}             - Discover peers on your local WiFi    │")
        print(f"{self.colors['info']}│                                                          │")
        print(f"{self.colors['info']}│ {Style.BRIGHT}CHATTING{Style.NORMAL}                                                 │")
        print(f"{self.colors['info']}│  {c1}/chat <name>{c2}      - Start a private chat session         │")
        print(f"{self.colors['info']}│  {c1}/gc_chat <name>{c2}   - Start a group chat session           │")
        print(f"{self.colors['info']}│  {c1}/sendimg <p> [m]{c2}  - Send an image (path, msg)            │")
        print(f"{self.colors['info']}│  {c1}/nearby <onion>{c2}   - Connect to a public relay lobby      │")
        print(f"{self.colors['info']}│  {c1}/goback{c2}           - Exit session and return to menu      │")
        print(f"{self.colors['info']}│                                                          │")
        print(f"{self.colors['info']}│ {Style.BRIGHT}GROUPS{Style.NORMAL}                                                   │")
        print(f"{self.colors['info']}│  {c1}/gc_create{c2}        - Create a group (name member1 ...)    │")
        print(f"{self.colors['info']}│  {c1}/gc_delete <g>{c2}    - Delete a group chat                  │")
        print(f"{self.colors['info']}│  {c1}/gc_kick <g> <f>{c2}  - Kick a member from a group           │")
        print(f"{self.colors['info']}└──────────────────────────────────────────────────────────┘")
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}Tip:{Style.NORMAL} Enter a chat with {c1}/chat <name>{reset}, then just type and press Enter.\n")

    def set_network(self, network):
        mode = network.lower()
        if mode in ["tor", "i2p", "both"]:
            self.config["network"] = mode
            self.save_config()
            print(f"{self.colors['success']}[+] Network set to: {mode.upper()}")
        else:
            print(f"{self.colors['error']}[!] Invalid network mode.")

    def add_friend(self, name, onion, key_path):
        fp = self.import_key(key_path)
        if fp:
            self.friends[name] = {'onion': onion, 'fingerprint': fp}
            self.save_friends()
            print(f"{self.colors['success']}[+] Friend '{name}' added!")

    def remove_friend(self, name):
        if name in self.friends:
            del self.friends[name]
            self.save_friends()
            print(f"{self.colors['success']}[+] Friend '{name}' removed.")

    def show_info(self):
        print(f"\n{self.colors['info']}=== MY INFO ===")
        print(f"{self.colors['success']}Onion Address: {Fore.WHITE}{self.onion_address}")
        print(f"{self.colors['success']}Fingerprint:   {Fore.WHITE}{self.my_fingerprint}")
        public_key = self.gpg.export_keys(self.my_fingerprint)
        with open("my_key.asc", 'w') as f:
            f.write(public_key)
        print(f"{self.colors['success']}Public Key exported to: {Fore.WHITE}my_key.asc")
        print(f"{self.colors['info']}===============\n")

    def stop(self):
        if self.tor_process:
            self.tor_process.kill()

    def run(self):
        print("""
  ░██████  ░██                                 ░██      ░██████  ░██                      ░██    
 ░██   ░██ ░██                                 ░██     ░██   ░██ ░██                      ░██    
░██        ░████████   ░███████   ░███████  ░████████ ░██        ░████████   ░██████   ░████████ 
░██  █████ ░██    ░██ ░██    ░██ ░██           ░██    ░██        ░██    ░██       ░██     ░██    
░██     ██ ░██    ░██ ░██    ░██  ░███████     ░██    ░██        ░██    ░██  ░███████     ░██    
 ░██  ░███ ░██    ░██ ░██    ░██        ░██    ░██     ░██   ░██ ░██    ░██ ░██   ░██     ░██    
  ░█████░█ ░██    ░██  ░███████   ░███████      ░████   ░██████  ░██    ░██  ░█████░██     ░████      


⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣦⠀
⠀⠀⠀⠀⣰⣿⡟⢻⣿⡟⢻⣧
⠀⠀⠀⣰⣿⣿⣇⣸⣿⣇⣸⣿
⠀⠀⣴⣿⣿⣿⣿⠟⢻⣿⣿⣿ -Fed's wont find us here 
⣠⣾⣿⣿⣿⣿⣿⣤⣼⣿⣿⠇
⢿⡿⢿⣿⣿⣿⣿⣿⣿⣿⡿⠀
⠀⠀⠈⠿⠿⠋⠙⢿⣿⡿⠁⠀                                                                                     
        """)
        print(f"{self.colors['info']}V1.3 By D3D5kull")
        print(f"{self.colors['info']}Tiktok: d3d5kull")
        
        self.start_tor()
        self.start_discovery()
        self.start_listener()
        
        self.show_help()
        
        while True:
            try:
                prompt_prefix = ""
                if self.current_group:
                    prompt_prefix = f"{Fore.YELLOW}[Group: {self.current_group}] "
                elif self.current_chat:
                    prompt_prefix = f"{Fore.GREEN}[Chat: {self.current_chat}] "
                
                cmd_raw = input(f"{prompt_prefix}{self.colors['prompt']}ghostchat> {Style.RESET_ALL}").strip()
                if not cmd_raw:
                    continue
                
                if not cmd_raw.startswith("/"):
                    if self.current_group:
                        self.send_message(None, cmd_raw, group_id=self.current_group)
                    elif self.current_chat:
                        self.send_message(self.current_chat, cmd_raw)
                    else:
                        print(f"{self.colors['error']}Not in a chat session. Use /chat <name> or /gc_chat <name> first.")
                    continue

                parts = cmd_raw.split(" ")
                cmd = parts[0]
                
                if cmd == "/quit":
                    break
                elif cmd == "/help":
                    self.show_help()
                elif cmd == "/clear":
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.show_help()
                elif cmd in ["/goback", "/exit"]:
                    self.current_chat = self.current_group = None
                    print(f"{self.colors['info']}Exited chat session.")
                elif cmd == "/myinfo":
                    self.show_info()
                elif cmd == "/setname":
                    if len(parts) > 1:
                        self.config['username'] = parts[1]
                        self.save_config()
                        print(f"{self.colors['success']}[+] Username set to: {parts[1]}")
                elif cmd == "/list":
                    f_list = ", ".join(self.friends.keys()) if self.friends else "None"
                    g_list = ", ".join(self.groups.keys()) if self.groups else "None"
                    print(f"{self.colors['info']}Friends: {f_list}")
                    print(f"{self.colors['info']}Groups: {g_list}")
                elif cmd == "/add" and len(parts) > 3:
                    self.add_friend(parts[1], parts[2], parts[3])
                elif cmd == "/remove" and len(parts) > 1:
                    self.remove_friend(parts[1])
                elif cmd == "/chat" and len(parts) > 1:
                    if parts[1] in self.friends:
                        self.current_chat = parts[1]
                        self.current_group = None
                        if len(parts) > 2:
                            self.send_message(parts[1], " ".join(parts[2:]))
                    else:
                        print(f"{self.colors['error']}[!] Friend '{parts[1]}' not found.")
                elif cmd == "/gc_chat" and len(parts) > 1:
                    if parts[1] in self.groups:
                        self.current_group = parts[1]
                        self.current_chat = None
                        if len(parts) > 2:
                            self.send_message(None, " ".join(parts[2:]), group_id=parts[1])
                    else:
                        print(f"{self.colors['error']}[!] Group '{parts[1]}' not found.")
                elif cmd == "/sendimg":
                    target = self.current_chat
                    img_idx = 1
                    if not target and len(parts) > 2:
                        target = parts[1]
                        img_idx = 2
                    
                    if target and len(parts) >= img_idx + 1:
                        msg = " ".join(parts[img_idx+1:]) if len(parts) > img_idx + 1 else "Image"
                        self.send_message(target, msg, image_path=parts[img_idx])
                    else:
                        print(f"{self.colors['error']}Usage: /sendimg [name] <path> [message]")
                elif cmd == "/network" and len(parts) > 1:
                    self.set_network(parts[1])
                elif cmd == "/gc_create" and len(parts) > 2:
                    self.groups[parts[1]] = {'members': parts[2:]}
                    self.save_groups()
                    print(f"{self.colors['success']}[+] Group '{parts[1]}' created.")
                elif cmd == "/gc_delete" and len(parts) > 1:
                    if parts[1] in self.groups:
                        del self.groups[parts[1]]
                        self.save_groups()
                        print(f"{self.colors['success']}[+] Group '{parts[1]}' deleted.")
                elif cmd == "/gc_kick" and len(parts) > 2:
                    if parts[1] in self.groups and parts[2] in self.groups[parts[1]]['members']:
                        self.groups[parts[1]]['members'].remove(parts[2])
                        self.save_groups()
                        print(f"{self.colors['success']}[+] Kicked {parts[2]} from {parts[1]}")
                elif cmd == "/scan":
                    self.scan_area()
                elif cmd == "/nearby" and len(parts) > 1:
                    self.send_message(parts[1], f"{self.config['username']} joined.")
                elif cmd == "/colors":
                    print(f"\n{self.colors['warn']}Customizable Colors:")
                    print("1. Prompt")
                    print("2. Message Sender")
                    print("3. Message Text")
                    print("4. Info")
                    print("5. Reset to defaults")
                    choice = input(f"{self.colors['prompt']}Choose element (1-5): {Style.RESET_ALL}")
                    if choice == "5":
                        self.config["colors"] = {}
                        self.save_config(); self._set_colors()
                        continue
                    print(f"\n{Fore.RED}RED {Fore.GREEN}GREEN {Fore.YELLOW}YELLOW {Fore.BLUE}BLUE {Fore.MAGENTA}MAGENTA {Fore.CYAN}CYAN {Fore.WHITE}WHITE")
                    color_name = input("Enter color name: ").upper()
                    if hasattr(Fore, color_name):
                        mapping = {"1": "prompt", "2": "msg_sender", "3": "msg_text", "4": "info"}
                        if choice in mapping:
                            self.config.setdefault("colors", {})[mapping[choice]] = getattr(Fore, color_name)
                            self.save_config(); self._set_colors()
                else:
                    print(f"{self.colors['error']}Unknown command.")
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{self.colors['error']}Error: {e}")

        self.stop()

if __name__ == "__main__":
    app = GhostChat()
    try:
        app.run()
    except KeyboardInterrupt:
        app.stop()
