import os
import asyncio
import aiohttp
import random
import hashlib
import time
import secrets
import base64
from typing import List, Optional, Dict
from urllib.parse import parse_qs, urlparse
from aiohttp_socks import ProxyConnector
from colorama import init, Fore, Style
from datetime import datetime
from yarl import URL

init(autoreset=True)

BORDER_WIDTH = 80

CLIENT_ID = "bVpvTmxJQ2xLY0pyVks2ZEhWb206MTpjaQ"
REDIRECT_URI = "https://meyhub.io/api/auth/twitter/callback"
SCOPE = "tweet.read users.read offline.access"
CODE_CHALLENGE_METHOD = "S256"
BEARER_TOKEN = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

MEYHUB_BACKEND = "https://meyhub.io"

CONFIG = {
    "DELAY_BETWEEN_ACCOUNTS": 3,
    "RETRY_ATTEMPTS": 3,
    "RETRY_DELAY": 5,
    "THREADS": 5,
    "TIMEOUT": 60,
}

TASKS = [
    {"name": "Follow Mey Network", "endpoint": "/api/actions/follow-mey-network"},
    {"name": "Join Telegram", "endpoint": "/api/actions/telegram-join"},
    {"name": "Join Discord", "endpoint": "/api/actions/discord-join"},
    {"name": "Follow on Instagram", "endpoint": "/api/actions/follow-instagram"},
    {"name": "Subscribe on Youtube", "endpoint": "/api/actions/subscribe-youtube"},
    {"name": "Follow on @0xLeonieZk", "endpoint": "/api/actions/follow-leonie"},
    {"name": "Follow on LinkedIn", "endpoint": "/api/actions/follow-linkedin"},
    {"name": "Follow on TikTok", "endpoint": "/api/actions/follow-tiktok"},
]

LANG = {
    'vi': {
        'title': 'MEYHUB AUTO SOCIAL - TWITTER LOGIN',
        'loading_accounts': 'Đang tải tài khoản Twitter...',
        'found_accounts': 'Tìm thấy {count} tài khoản',
        'loading_proxies': 'Đang tải proxy...',
        'found_proxies': 'Tìm thấy {count} proxy',
        'no_proxies': 'Không tìm thấy proxy, chạy không proxy',
        'processing': '⚙ ĐANG XỬ LÝ {count} TÀI KHOẢN',
        'twitter_auth': 'Đang xác thực Twitter...',
        'twitter_auth_success': 'Twitter xác thực thành công!',
        'twitter_auth_failed': 'Twitter xác thực thất bại',
        'logging_in': 'Đang đăng nhập Meyhub...',
        'login_success': 'Đăng nhập thành công!',
        'login_failed': 'Đăng nhập thất bại',
        'completing_task': 'Đang hoàn thành nhiệm vụ',
        'task_success': 'Nhiệm vụ thành công!',
        'task_failed': 'Nhiệm vụ thất bại',
        'task_awarded': 'Được thưởng',
        'already_done': 'Đã thực hiện trước đó',
        'success': '✅ Thành công',
        'failed': '❌ Thất bại',
        'error': 'Lỗi',
        'using_proxy': 'Proxy',
        'no_proxy': 'Không proxy',
        'completed': '✅ HOÀN THÀNH: {successful}/{total} TÀI KHOẢN THÀNH CÔNG',
        'pausing': 'Tạm dừng',
        'seconds': 'giây',
        'account': 'Tài khoản',
        'public_ip': 'IP công khai',
        'unknown': 'Không xác định',
    },
    'en': {
        'title': 'MEYHUB AUTO SOCIAL - TWITTER LOGIN',
        'loading_accounts': 'Loading Twitter accounts...',
        'found_accounts': 'Found {count} accounts',
        'loading_proxies': 'Loading proxies...',
        'found_proxies': 'Found {count} proxies',
        'no_proxies': 'No proxies found, running without proxy',
        'processing': '⚙ PROCESSING {count} ACCOUNTS',
        'twitter_auth': 'Authenticating Twitter...',
        'twitter_auth_success': 'Twitter authentication successful!',
        'twitter_auth_failed': 'Twitter authentication failed',
        'logging_in': 'Logging in to Meyhub...',
        'login_success': 'Login successful!',
        'login_failed': 'Login failed',
        'completing_task': 'Completing task',
        'task_success': 'Task successful!',
        'task_failed': 'Task failed',
        'task_awarded': 'Awarded',
        'already_done': 'Already done previously',
        'success': '✅ Success',
        'failed': '❌ Failed',
        'error': 'Error',
        'using_proxy': 'Proxy',
        'no_proxy': 'No proxy',
        'completed': '✅ COMPLETED: {successful}/{total} ACCOUNTS SUCCESSFUL',
        'pausing': 'Pausing',
        'seconds': 'seconds',
        'account': 'Account',
        'public_ip': 'Public IP',
        'unknown': 'Unknown',
    }
}

def print_border(text: str, color=Fore.CYAN, language='vi'):
    width = BORDER_WIDTH
    if len(text) > width - 4:
        text = text[:width - 7] + "..."
    padded_text = f" {text} ".center(width - 2)
    print(f"{color}┌{'─' * (width - 2)}┐{Style.RESET_ALL}")
    print(f"{color}│{padded_text}│{Style.RESET_ALL}")
    print(f"{color}└{'─' * (width - 2)}┘{Style.RESET_ALL}")

def print_separator(color=Fore.MAGENTA):
    print(f"{color}{'═' * BORDER_WIDTH}{Style.RESET_ALL}")

def print_message(text: str, color=Fore.WHITE, language='vi'):
    print(f"{color}  {text}{Style.RESET_ALL}")

def generate_fingerprint(account_index: int) -> dict:
    seed = f"meyhub_{account_index}_{time.time()}"
    hash_val = hashlib.md5(seed.encode()).hexdigest()
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    ]
    
    return {
        "user_agent": user_agents[int(hash_val[:2], 16) % len(user_agents)],
        "fp_hash": hash_val[:12]
    }

def generate_state() -> str:
    return f"v_{random.randint(10000000, 99999999)}"

def generate_pkce():
    verifier = secrets.token_urlsafe(96)
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return verifier, challenge

def load_accounts(filepath: str, language='vi') -> List[Dict]:
    if not os.path.exists(filepath):
        print(f"{Fore.RED}  ❌ File {filepath} không tìm thấy!{Style.RESET_ALL}")
        return []
    
    accounts = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if '|' in line:
                    parts = line.split('|')
                elif ':' in line:
                    parts = line.split(':')
                else:
                    continue
                
                if len(parts) >= 2:
                    accounts.append({
                        "auth_token": parts[0].strip(),
                        "ct0": parts[1].strip()
                    })
        
        if not accounts:
            print(f"{Fore.RED}  ❌ Không tìm thấy tài khoản hợp lệ trong {filepath}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}  ❌ Lỗi đọc file: {str(e)}{Style.RESET_ALL}")
    
    return accounts

def load_proxies(language='vi') -> List[str]:
    if not os.path.exists('proxies.txt'):
        print(f"{Fore.YELLOW}  ℹ {LANG[language]['no_proxies']}{Style.RESET_ALL}")
        return []
    
    proxies = []
    with open('proxies.txt', 'r', encoding='utf-8') as f:
        for line in f:
            proxy = line.strip()
            if proxy and not proxy.startswith('#'):
                proxies.append(proxy)
    
    if proxies:
        print(f"{Fore.YELLOW}  ℹ {LANG[language]['found_proxies'].format(count=len(proxies))}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}  ℹ {LANG[language]['no_proxies']}{Style.RESET_ALL}")
    
    return proxies

def parse_proxy(proxy: str) -> Optional[str]:
    if not proxy:
        return None
    
    try:
        if '://' in proxy:
            return proxy
        
        parts = proxy.split(':')
        if len(parts) == 2:
            return f"http://{parts[0]}:{parts[1]}"
        elif len(parts) == 4:
            return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
        
    except:
        pass
    
    return None

async def check_proxy_ip(session: aiohttp.ClientSession) -> str:
    try:
        async with session.get('https://api.ipify.org?format=json', timeout=10) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get('ip', 'Unknown')
    except:
        pass
    return 'Unknown'

class TwitterOAuth:
    def __init__(self, auth_token: str, ct0: str, fingerprint: dict, session: aiohttp.ClientSession):
        self.auth_token = auth_token
        self.ct0 = ct0
        self.fingerprint = fingerprint
        self.session = session
    
    def _get_headers(self, referer: str = None) -> dict:
        headers = {
            "User-Agent": self.fingerprint["user_agent"],
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Authorization": f"Bearer {BEARER_TOKEN}",
            "X-Csrf-Token": self.ct0,
            "x-twitter-active-user": "yes",
            "x-twitter-auth-type": "OAuth2Session",
            "x-twitter-client-language": "en",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        
        if referer:
            headers["Referer"] = referer
        
        return headers
    
    def _get_cookies(self) -> dict:
        return {
            "auth_token": self.auth_token,
            "ct0": self.ct0,
        }
    
    async def get_authorization_code(self, state: str, challenge: str) -> Optional[str]:
        auth_url = "https://twitter.com/i/api/2/oauth2/authorize"
        
        params = {
            "client_id": CLIENT_ID,
            "code_challenge": challenge,
            "code_challenge_method": CODE_CHALLENGE_METHOD,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": SCOPE,
            "state": state
        }
        
        referer = f"https://twitter.com/i/oauth2/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE.replace(' ', '%20')}&state={state}&code_challenge={challenge}&code_challenge_method={CODE_CHALLENGE_METHOD}"
        
        try:
            async with self.session.get(
                auth_url,
                params=params,
                headers=self._get_headers(referer),
                cookies=self._get_cookies(),
                timeout=CONFIG['TIMEOUT']
            ) as resp:
                if resp.status != 200:
                    return None
                
                data = await resp.json()
                auth_code = data.get("auth_code")
                
                if not auth_code:
                    return None
                
                return await self._approve_authorization(auth_code, state, challenge)
        except:
            return None
    
    async def _approve_authorization(self, auth_code: str, state: str, challenge: str) -> Optional[str]:
        approve_url = "https://twitter.com/i/api/2/oauth2/authorize"
        
        referer = f"https://twitter.com/i/oauth2/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE.replace(' ', '%20')}&state={state}&code_challenge={challenge}&code_challenge_method={CODE_CHALLENGE_METHOD}"
        
        headers = self._get_headers(referer)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        data = f"approval=true&code={auth_code}"
        
        try:
            async with self.session.post(
                approve_url,
                headers=headers,
                cookies=self._get_cookies(),
                data=data,
                timeout=CONFIG['TIMEOUT']
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    redirect_uri = result.get("redirect_uri", "")
                    
                    if redirect_uri:
                        parsed = urlparse(redirect_uri)
                        query_params = parse_qs(parsed.query)
                        if 'code' in query_params:
                            return query_params['code'][0]
        except:
            pass
        
        return None

class MeyhubAPI:
    def __init__(self, fingerprint: dict, session: aiohttp.ClientSession):
        self.fingerprint = fingerprint
        self.session = session
    
    async def handle_oauth_callback(self, code: str, state: str, verifier: str) -> bool:
        callback_url = f"{REDIRECT_URI}?code={code}&state={state}"
        
        cookies_to_set = {
            "twitter_code_verifier": verifier,
            "twitter_state": state,
            "twitter_referral": "d1jE-pRM_P"
        }
        self.session.cookie_jar.update_cookies(cookies_to_set, URL(MEYHUB_BACKEND))
        
        headers = {
            "User-Agent": self.fingerprint["user_agent"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "vi,en-US;q=0.9,en;q=0.8,fr-FR;q=0.7,fr;q=0.6",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Referer": "https://x.com/",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Priority": "u=0, i",
        }
        
        try:
            async with self.session.get(
                callback_url,
                headers=headers,
                allow_redirects=False,
                timeout=CONFIG['TIMEOUT']
            ) as resp:
                cookies = self.session.cookie_jar.filter_cookies(URL(MEYHUB_BACKEND))
                if 'session' in cookies:
                    return True
        except:
            pass
        
        return False
    
    async def complete_task(self, endpoint: str) -> Optional[dict]:
        url = f"{MEYHUB_BACKEND}{endpoint}"
        
        headers = {
            "User-Agent": self.fingerprint["user_agent"],
            "Accept": "*/*",
            "Accept-Language": "vi,en-US;q=0.9,en;q=0.8,fr-FR;q=0.7,fr;q=0.6",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Length": "0",
            "Origin": "https://meyhub.io",
            "Referer": "https://meyhub.io/dashboard",
            "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "Priority": "u=1, i",
        }
        
        try:
            async with self.session.post(
                url,
                headers=headers,
                timeout=CONFIG['TIMEOUT']
            ) as resp:
                if resp.status == 200:
                    try:
                        result = await resp.json()
                        return result
                    except:
                        return {"success": True}
        except:
            pass
        
        return None

async def process_account(account: dict, account_index: int, proxy: Optional[str], language: str) -> bool:
    auth_token = account['auth_token']
    ct0 = account['ct0']
    
    fingerprint = generate_fingerprint(account_index)
    
    print(f"{Fore.MAGENTA}{'─' * BORDER_WIDTH}{Style.RESET_ALL}")
    print()
    print(f"{Fore.CYAN}  Tài khoản #{account_index + 1} (FP: {fingerprint['fp_hash']}){Style.RESET_ALL}")
    print()
    
    connector = None
    if proxy:
        proxy_url = parse_proxy(proxy)
        if proxy_url:
            connector = ProxyConnector.from_url(proxy_url)
    
    timeout = aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        if proxy:
            public_ip = await check_proxy_ip(session)
            print(f"{Fore.CYAN}  🔄 Proxy: {proxy} | IP công khai: {public_ip}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}  > {LANG[language]['twitter_auth']}{Style.RESET_ALL}")
        
        verifier, challenge = generate_pkce()
        state = generate_state()
        
        twitter_oauth = TwitterOAuth(auth_token, ct0, fingerprint, session)
        twitter_code = await twitter_oauth.get_authorization_code(state, challenge)
        
        if not twitter_code:
            print(f"{Fore.RED}  ✖ {LANG[language]['twitter_auth_failed']}{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.GREEN}  ✓ {LANG[language]['twitter_auth_success']}{Style.RESET_ALL}")
        await asyncio.sleep(random.uniform(0.5, 1))
        
        print(f"{Fore.CYAN}  > {LANG[language]['logging_in']}{Style.RESET_ALL}")
        
        meyhub_api = MeyhubAPI(fingerprint, session)
        login_success = await meyhub_api.handle_oauth_callback(twitter_code, state, verifier)
        
        if not login_success:
            print(f"{Fore.RED}  ✖ {LANG[language]['login_failed']}{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.GREEN}  ✓ {LANG[language]['login_success']}{Style.RESET_ALL}")
        await asyncio.sleep(random.uniform(0.5, 1))
        
        for task in TASKS:
            task_name = task['name']
            endpoint = task['endpoint']
            
            print(f"{Fore.CYAN}  > {LANG[language]['completing_task']}: {task_name}{Style.RESET_ALL}")
            
            task_data = await meyhub_api.complete_task(endpoint)
            
            if task_data and task_data.get('success'):
                print(f"{Fore.GREEN}  ✓ {LANG[language]['task_success']}{Style.RESET_ALL}")
                if task_data.get('awarded'):
                    print(f"{Fore.YELLOW}  - {LANG[language]['task_awarded']}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}  - {LANG[language]['already_done']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}  ✖ {LANG[language]['task_failed']}{Style.RESET_ALL}")
            
            await asyncio.sleep(random.uniform(0.5, 1))
        
        print()
        print(f"{Fore.GREEN}  ✅ {LANG[language]['success']}{Style.RESET_ALL}")
        print()
        
        return True

async def run_socialX(language: str = 'vi'):
    print()
    print_border(LANG[language]['title'], Fore.CYAN, language)
    print()
    
    proxies = load_proxies(language)
    print()
    
    accounts = load_accounts('tokenX.txt', language)
    print(f"{Fore.YELLOW}  ℹ {LANG[language]['found_accounts'].format(count=len(accounts))}{Style.RESET_ALL}")
    print()
    
    if not accounts:
        return
    
    print_separator()
    print_border(LANG[language]['processing'].format(count=len(accounts)), Fore.MAGENTA, language)
    print()
    
    successful = 0
    total = len(accounts)
    
    semaphore = asyncio.Semaphore(CONFIG['THREADS'])
    
    async def process_with_semaphore(idx, acc):
        nonlocal successful
        async with semaphore:
            proxy = proxies[idx % len(proxies)] if proxies else None
            success = await process_account(acc, idx, proxy, language)
            if success:
                successful += 1
            
            if idx < total - 1:
                delay = CONFIG['DELAY_BETWEEN_ACCOUNTS']
                print_message(f"{LANG[language]['pausing']} {delay} {LANG[language]['seconds']}...", Fore.YELLOW, language)
                await asyncio.sleep(delay)
    
    tasks = [process_with_semaphore(i, acc) for i, acc in enumerate(accounts)]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    print()
    print_border(LANG[language]['completed'].format(successful=successful, total=total), Fore.GREEN, language)
    print()

if __name__ == "__main__":
    asyncio.run(run_socialX('vi'))
