import os
import sys
import time
import socket
import threading
import json
import shutil
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
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
APP_PORT = 13337  # Local port for the app to listen on
ONION_PORT = 80   # Port exposed on the onion address

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
        self.config = self.load_config()
        self.my_fingerprint = None
        
        # Setup GPG
        self.setup_gpg()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {"username": "Ghost"}

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

    def setup_gpg(self):
        # Check for existing keys
        keys = self.gpg.list_keys(secret=True)
        if not keys:
            print(f"{Fore.YELLOW}[*] Generating new GPG keypair for GhostChat... This may take a moment.")
            input_data = self.gpg.gen_key_input(
                key_type="RSA",
                key_length=2048,
                name_real="GhostChat User",
                name_email="ghost@chat.local",
                no_protection=True # No passphrase for simplicity in this script
            )
            key = self.gpg.gen_key(input_data)
            self.my_fingerprint = key.fingerprint
            print(f"{Fore.GREEN}[+] Key generated: {self.my_fingerprint}")
        else:
            self.my_fingerprint = keys[0]['fingerprint']
            print(f"{Fore.GREEN}[+] Loaded existing key: {self.my_fingerprint}")

    def _find_tor_executable(self):
        # Check if tor is in PATH
        tor_path = shutil.which("tor")
        if tor_path:
            return tor_path
        
        # Check common locations
        common_paths = [
            "/usr/sbin/tor", 
            "/usr/local/bin/tor", 
            "/opt/homebrew/bin/tor",
            "/data/data/com.termux/files/usr/bin/tor"  # Termux path
        ]
        for path in common_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        return None

    def start_tor(self):
        print(f"{Fore.YELLOW}[*] Launching Tor... (This can take a minute)")
        
        tor_cmd = self._find_tor_executable()
        if not tor_cmd:
            print(f"{Fore.RED}[!] 'tor' executable not found in PATH or common locations.")
            print(f"{Fore.RED}[!] Please install Tor or add it to your PATH.")
            sys.exit(1)

        try:
            # We use a custom torrc configuration
            self.tor_process = launch_tor_with_config(
                config={
                    'SocksPort': str(TOR_SOCKS_PORT),
                    'ControlPort': str(TOR_CONTROL_PORT),
                    'DataDirectory': TOR_DIR,
                    'HiddenServiceDir': os.path.join(TOR_DIR, 'hs'),
                    'HiddenServicePort': f'{ONION_PORT} 127.0.0.1:{APP_PORT}',
                },
                tor_cmd=tor_cmd,
                take_ownership=True,  # Process closes when script closes
                init_msg_handler=lambda line: print(f"{Fore.CYAN}[Tor] {line}") if "Bootstrapped" in line else None,
            )
        except OSError as e:
            print(f"{Fore.RED}[!] Failed to launch Tor: {e}")
            print(f"{Fore.RED}[!] Ensure 'tor' is installed and in your PATH.")
            sys.exit(1)

        # Connect to controller to get onion address
        try:
            self.controller = Controller.from_port(port=TOR_CONTROL_PORT)
            self.controller.authenticate()
            
            # Read hostname
            hs_dir = os.path.join(TOR_DIR, 'hs', 'hostname')
            while not os.path.exists(hs_dir):
                time.sleep(1)
            
            with open(hs_dir, 'r') as f:
                self.onion_address = f.read().strip()
                
            print(f"{Fore.GREEN}[+] Tor Ready!")
            print(f"{Fore.GREEN}[+] My Onion Address: {Fore.WHITE}{self.onion_address}")
            
            # Save original socket before monkeypatching
            self.original_socket = socket.socket
            
            # Set default proxy for socket
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", TOR_SOCKS_PORT)
            socket.socket = socks.socksocket
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error connecting to Tor controller: {e}")
            self.stop()
            sys.exit(1)

    def start_listener(self):
        server_thread = threading.Thread(target=self._listen_loop, daemon=True)
        server_thread.start()

    def _listen_loop(self):
        # Wait until Tor is ready and original_socket is saved
        while not hasattr(self, 'original_socket'):
            time.sleep(0.5)

        # Create a raw socket (not socks) for listening on localhost
        # We must bypass the global socket monkeypatch for the listener
        # because we bind to 127.0.0.1, not through Tor
        s = self.original_socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', APP_PORT))
        s.listen(5)
        
        while True:
            conn, addr = s.accept()
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _handle_client(self, conn):
        try:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            
            # Decrypt
            decrypted = self.gpg.decrypt(data.decode('utf-8', errors='ignore'))
            
            if decrypted.ok:
                # Parse JSON payload
                try:
                    payload = json.loads(decrypted.data.decode())
                    msg_text = payload.get('m', 'Empty message')
                    sender_defined_username = payload.get('u', 'Ghost')
                except:
                    # Fallback for old protocol
                    msg_text = decrypted.data.decode()
                    sender_defined_username = "Unknown"

                # Identify sender by fingerprint
                sender_name = "Unknown"
                if decrypted.fingerprint:
                    for name, f_data in self.friends.items():
                        if f_data['fingerprint'] == decrypted.fingerprint:
                            sender_name = name
                            break
                    if sender_name == "Unknown":
                        sender_name = f"ID:{decrypted.fingerprint[-8:]}"

                # Final display: [MyLocalName (TheirUsername)] Message
                display_name = f"{sender_name} ({sender_defined_username})" if sender_name != sender_defined_username else sender_name
                print(f"\n{Fore.MAGENTA}[{display_name}] {Fore.WHITE}{msg_text}")
                print(f"{Fore.BLUE}ghostchat> {Style.RESET_ALL}", end="", flush=True)
            else:
                print(f"\n{Fore.RED}[!] Received message but failed to decrypt: {decrypted.status}")
                print(f"{Fore.BLUE}ghostchat> {Style.RESET_ALL}", end="", flush=True)

        except Exception as e:
            # print(f"\n[!] Error handling message: {e}")
            pass
        finally:
            conn.close()

    def send_message(self, onion, msg):
        # Find friend fingerprint
        fingerprint = None
        for name, data in self.friends.items():
            if data['onion'] == onion:
                fingerprint = data['fingerprint']
                break
        
        if not fingerprint:
            # Check if onion is actually a name
            if onion in self.friends:
                fingerprint = self.friends[onion]['fingerprint']
                onion = self.friends[onion]['onion'] # resolve name to onion
            else:
                print(f"{Fore.RED}[!] Friend not found. Add them first.")
                return

        # Prepare JSON payload
        payload = json.dumps({
            "u": self.config.get("username", "Ghost"),
            "m": msg
        })

        # Encrypt and Sign
        print(f"{Fore.YELLOW}[*] Encrypting and Signing for {fingerprint}...")
        encrypted = self.gpg.encrypt(
            payload, 
            fingerprint, 
            sign=self.my_fingerprint, 
            always_trust=True
        )
        if not encrypted.ok:
            print(f"{Fore.RED}[!] Encryption failed: {encrypted.status}")
            return

        # Send
        print(f"{Fore.YELLOW}[*] Connecting to {onion}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30) # Tor can be slow
            s.connect((onion, ONION_PORT))
            s.sendall(str(encrypted).encode('utf-8'))
            s.close()
            print(f"{Fore.GREEN}[+] Sent!")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to send: {e}")

    def import_key(self, path):
        if not os.path.exists(path):
            print(f"{Fore.RED}[!] File not found: {path}")
            return None
        
        with open(path, 'r') as f:
            key_data = f.read()
            
        import_result = self.gpg.import_keys(key_data)
        if import_result.count > 0:
            fp = import_result.fingerprints[0]
            print(f"{Fore.GREEN}[+] Imported key: {fp}")
            return fp
        else:
            print(f"{Fore.RED}[!] No valid keys found in file.")
            return None

    def add_friend(self, name, onion, key_path):
        fp = self.import_key(key_path)
        if fp:
            self.friends[name] = {'onion': onion, 'fingerprint': fp}
            self.save_friends()
            print(f"{Fore.GREEN}[+] Friend '{name}' added!")

    def remove_friend(self, name):
        if name in self.friends:
            del self.friends[name]
            self.save_friends()
            print(f"{Fore.GREEN}[+] Friend '{name}' removed.")
        else:
            print(f"{Fore.RED}[!] Friend '{name}' not found.")

    def show_info(self):
        print(f"\n{Fore.CYAN}=== MY INFO ===")
        print(f"{Fore.GREEN}Onion Address: {Fore.WHITE}{self.onion_address}")
        print(f"{Fore.GREEN}Fingerprint:   {Fore.WHITE}{self.my_fingerprint}")
        
        public_key = self.gpg.export_keys(self.my_fingerprint)
        key_path = "my_key.asc"
        with open(key_path, 'w') as f:
            f.write(public_key)
        print(f"{Fore.GREEN}Public Key exported to: {Fore.WHITE}{os.path.abspath(key_path)}")
        print(f"{Fore.CYAN}===============\n")

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
        print(f"{Fore.CYAN}V1.0 By D3D5kull")
        print(f"{Fore.CYAN}Tiktok: d3d5kull")
        


    
        
        self.start_tor()
        self.start_listener()
        
        print(f"\n{Fore.YELLOW}Commands:")
        print("  /myinfo                   - Show your address and key")
        print("  /setname <new_name>       - Set your custom username")
        print("  /add <name> <onion> <key_file> - Add a friend")
        print("  /remove <name>            - Remove a friend")
        print("  /chat <name> <msg>        - Send a message")
        print("  /list                     - List friends")
        print("  /quit                     - Exit")
        
        while True:
            try:
                cmd_raw = input(f"{Fore.BLUE}ghostchat> {Style.RESET_ALL}").strip()
                if not cmd_raw:
                    continue
                
                parts = cmd_raw.split(" ", 2)
                cmd = parts[0]
                
                if cmd == "/quit":
                    break
                elif cmd == "/myinfo":
                    self.show_info()
                elif cmd == "/setname":
                    if len(parts) < 2:
                        print(f"{Fore.RED}Usage: /setname <new_name>")
                    else:
                        self.config['username'] = parts[1]
                        self.save_config()
                        print(f"{Fore.GREEN}[+] Username set to: {parts[1]}")
                elif cmd == "/list":
                    print(f"{Fore.CYAN}Friends:")
                    for name, data in self.friends.items():
                        print(f"  - {name}: {data['onion']}")
                elif cmd == "/add":
                    if len(parts) < 3:
                        print(f"{Fore.RED}Usage: /add <name> <onion> <key_file>")
                    else:
                        args = cmd_raw.split()
                        if len(args) != 4:
                             print(f"{Fore.RED}Usage: /add <name> <onion> <key_file> (No spaces in names)")
                        else:
                            self.add_friend(args[1], args[2], args[3])
                elif cmd == "/remove":
                    if len(parts) < 2:
                        print(f"{Fore.RED}Usage: /remove <name>")
                    else:
                        self.remove_friend(parts[1])
                elif cmd == "/chat":
                    if len(parts) < 3:
                        print(f"{Fore.RED}Usage: /chat <name> <message>")
                    else:
                        self.send_message(parts[1], parts[2])
                else:
                    print(f"{Fore.RED}Unknown command.")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Fore.RED}Error: {e}")

        self.stop()
        print("Bye!")

if __name__ == "__main__":
    app = GhostChat()
    try:
        app.run()
    except KeyboardInterrupt:
        app.stop()
