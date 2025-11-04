from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import formatdate
from typing import Any, Tuple, List, Dict, Union
from urllib.parse import urlencode, quote, parse_qs
import base64
import hashlib
import hmac
import json
import logging
import os
import qrcode_terminal
import re
import requests
import secrets
import shlex
import string
import subprocess
import sys
import tempfile
import time
import urllib
import threading
# ANSI Color Codes
COLOR_FOLDER = '\033[0m'
COLOR_FILE = '\033[0m'
COLOR_SIZE_SMALL = '\033[92m'
COLOR_SIZE_MEDIUM = '\033[93m'
COLOR_SIZE_LARGE3 = '\033[91m'
COLOR_SIZE_LARGE = '\033[96m'
COLOR_SIZE_LARGE2 = '\033[95m'
COLOR_RESET = '\033[0m'
logging.basicConfig(level=logging.INFO, format='%(message)s')
CMD_RENDER_NEEDED = "render_needed"
CMD_CONTINUE_INPUT = "continue_input"
CMD_EXIT = "exit"

#临时绕过 SSL 验证（本地调试用）
# 在 _call_api 中添加 verify=False
#response = requests.get(url, headers=headers, params=params, timeout=..., verify=False)

# === 新增：通用辅助函数 ===
def extract_fids(items: List[Dict]) -> List[str]:
    """从 item 列表中提取 fid 列表"""
    return [_get_item_attribute(item, "fid", "file_id") for item in items if _get_item_attribute(item, "fid", "file_id")]

def join_relative_path(base: str, name: str) -> str:
    """安全地拼接相对路径"""
    return os.path.join(base, name).replace("\\", "/")

class AppConfig:
    def __init__(self):
        self.FILE_LIST_API_URL = "https://proapi.115.com/open/ufile/files"
        self.SEARCH_API_URL = "https://proapi.115.com/open/ufile/search"
        self.DOWNLOAD_API_URL = "https://proapi.115.com/open/ufile/downurl"
        self.REFERER_DOMAIN = "https://proapi.115.com/"
        self.GET_FOLDER_INFO_API_URL = "https://proapi.115.com/open/folder/get_info"
        self.MOVE_API_URL = "https://proapi.115.com/open/ufile/move"
        self.ADD_FOLDER_API_URL = "https://proapi.115.com/open/folder/add"
        self.UPDATE_FILE_API_URL = "https://proapi.115.com/open/ufile/update"
        self.DELETE_FILE_API_URL = "https://proapi.115.com/open/ufile/delete"
        self.CLOUD_DOWNLOAD_API_URL = "https://proapi.115.com/open/offline/add_task_urls"
        self.AUTH_DEVICE_CODE_URL = "https://passportapi.115.com/open/authDeviceCode"
        self.QRCODE_STATUS_URL = "https://qrcodeapi.115.com/get/status/"
        self.DEVICE_CODE_TO_TOKEN_URL = "https://passportapi.115.com/open/deviceCodeToToken"
        self.REFRESH_TOKEN_URL = "https://passportapi.115.com/open/refreshToken"
        self.GET_UPLOAD_TOKEN_API_URL = "https://proapi.115.com/open/upload/get_token"
        self.UPLOAD_INIT_API_URL = "https://proapi.115.com/open/upload/init"
        self.UPLOAD_RESUME_API_URL = "https://proapi.115.com/open/upload/resume"
        self.RCLONE_TOKEN_FULL_PATH = "790:p/.config/cloud/my115/token.txt"
        self.USER_AGENT = "Infuse/8.3.5401"
        self.CLIENT_ID = self._get_client_id(4)
        self.DEFAULT_CONNECT_TIMEOUT = 300
        self.DEFAULT_READ_TIMEOUT = 300
        self.MAX_SEARCH_EXPLORE_COUNT = 10000
        self.API_FETCH_LIMIT = 1150
        self.PAGINATOR_DISPLAY_SIZE = self._get_default_display_size()
        self.ROOT_CID = '0'
        self.ALLOWED_SPECIAL_FILENAME_CHARS = "._- ()[]{}+#@&"
        self.MAX_SAFE_FILENAME_LENGTH = 1150
        self.DEFAULT_TARGET_DOWNLOAD_DIR = self._get_default_download_dir()
        self.JSON_OUTPUT_SUBDIR = 'json'
        self.MOVE_LOG_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)), "move_log.json")
        # === 下载/上传线程池（保留，无开关）===
        self.DOWNLOAD_CONCURRENT_THREADS = 10
        self.UPLOAD_CONCURRENT_THREADS = 4
        # === RPS and Thread Pool Control ===
        self.API_RPS_LIMIT = 2  # 每秒最多API请求次数
        self.API_CONCURRENT_THREADS = 10             # ← 控制所有 API 线程池的最大并发线程数
        self.MULTIPART_UPLOAD_MIN_SIZE = 20 * 1024 * 1024
        self.SMALL_FILE_MAX_SIZE_FOR_5MB_CHUNKS = 50 * 1024 * 1024
        self.CUSTOM_CHUNK_SIZE_FOR_SMALL_FILES = 20 * 1024 * 1024
        self.LARGE_FILE_FIXED_CHUNK_SIZE = 20 * 1024 * 1024
        self.UPLOAD_RETRY_COUNT = 3
        self.UPLOAD_RETRY_DELAY_SECONDS = 5
        self.COMMON_BROWSE_FETCH_PARAMS = {
            "o": "file_name",
            "asc": "1",
            "show_dir": "1",
            "custom_order": "1"
        }
        self.PREDEFINED_FETCH_PARAMS = {
            "default_browse": {
                "description": "Default browse settings",
                "params": self.COMMON_BROWSE_FETCH_PARAMS.copy()
            }
        }
        self.PREDEFINED_SAVE_FOLDERS = {
            '电影-大陆': 3112727343181216340,
            '电影-日本': 3112727439373383983,
            '电影-韩国': 3112727519769803583,
            '电影-港台': 3112727590276053143,
            '电影-欧美': 3112727716725930799,
            '电影-俄语': 3112727775546850302,
            '电影-动画': 3112728039435680623,
            '剧集-动画': 3112728111208610094,
            '电影-亚太': 3112728334228143032,
            '剧集-大陆': 3112728464394172531,
            '电影-其他': 3112728659647412567,
            '剧集-其他': 3112728782179809739,
            '剧集-日本': 3112728920910608942,
            '剧集-韩国': 3112728980880767691,
            '剧集-港台': 3112729076200519975,
            '剧集-欧美': 3112729152780122643,
            '剧集-亚太': 3112729228186931828,
            '剧集-俄语': 3112729350281509084,
            '电视节目': 3112736070923860587,
            '演唱会': 3112736166268779042,
            '纪录片': 3112736229787318869,
            '其他文件': 3112736324528257038,
            'ns': 3090049925983386006
        }
        self.PREDEFINED_UPLOAD_FOLDERS = self.PREDEFINED_SAVE_FOLDERS
        self.DEFAULT_PLAYBACK_STRATEGY = 1
        self.access_token: Union[str, None] = None
        self.show_list_short_form: bool = True
        self.search_more_query: bool = False
        self.enable_concurrent_c_details_fetching: bool = False
        #移动功能相关参数
        self.MOVE_MAX_FILE_IDS = 100000
        self.MOVE_RATE_LIMIT_FILES_PER_SECOND = 6000
    def _get_default_download_dir(self):
        if "TERMUX_VERSION" in os.environ:
            return os.path.join(os.path.expanduser('~'), 'storage', 'shared', 'Alist', 'aria2')
        else:
            return os.path.join(os.path.expanduser('~'), 'Downloads', 'aria2')
    def _get_default_display_size(self):
        if "TERMUX_VERSION" in os.environ:
            return 10
        else:
            return 23
    def _get_client_id(self, app):
        app_dict = {
            1: 100195135,
            2: 100195145,
            3: 100195181,
            4: 100196251,
            5: 100195137,
            6: 100195161,
            7: 100197303,
            8: 100195313
        }
        return app_dict.get(app, "App name not found")
# === RPS 控制器 ===
class RateLimiter:
    def __init__(self, rps: int):
        self.rps = rps
        self.interval = 1.0 / rps
        self.last_call = 0
        self.lock = threading.Lock()
    def acquire(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_call
            if elapsed < self.interval:
                sleep_time = self.interval - elapsed
                time.sleep(sleep_time)
            self.last_call = time.time()
# 全局 RPS 限速器（所有 API 共用）
_global_api_limiter = None
class ApiService:
    def __init__(self, config: AppConfig):
        self.config = config
        self.token = TokenManager(self.config)
        self.config.access_token = self.token.get_access_token_from_file()
        global _global_api_limiter
        _global_api_limiter = RateLimiter(config.API_RPS_LIMIT)
    # ============= 新增：统一并发函数 =============
    def _fetch_concurrent_pages(self, fetch_func: callable, fetch_args_list: List[Dict]) -> List[Any]:
        """
        通用并发 API 调用函数。
        fetch_func: 要调用的 API 函数（如 self.fetch_files_in_directory_page）
        fetch_args_list: 参数列表，每个元素是传给 fetch_func 的 kwargs dict
        返回：[result1, result2, ...] 顺序与输入一致
        """
        if not fetch_args_list:
            return []
        results = [None] * len(fetch_args_list)
        with ThreadPoolExecutor(max_workers=self.config.API_CONCURRENT_THREADS) as executor:
            futures = {
                executor.submit(fetch_func, **args): i
                for i, args in enumerate(fetch_args_list)
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    logging.error(f"Concurrent API call failed at index {idx}: {e}")
                    results[idx] = None
        return results
    def _rate_limited_call(self, func, *args, **kwargs):
        _global_api_limiter.acquire()
        return func(*args, **kwargs)
    def _execute_shell_command(self, command: List[str]) -> Tuple[int, str, str]:
        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            return process.returncode, process.stdout.strip(), process.stderr.strip()
        except FileNotFoundError:
            logging.error(f"Error: Command not found. Please ensure '{command[0]}' is installed and in your PATH.")
            return -1, "", f"Command '{command[0]}' not found."
        except Exception as e:
            logging.error(f"An unexpected error occurred while executing command: {e}")
            return -1, "", str(e)
    def _refresh_access_token(self) -> bool:
        try:
            access_token = self.token.refresh_and_get_new_token()
            if access_token:
                self.config.access_token = access_token
                return True
        except Exception as e:
            logging.error(f"An unexpected error occurred while parsing remote token file '{self.config.RCLONE_TOKEN_FULL_PATH}': {e}")
            return False
    def _build_api_params(self, base_params: Dict, **kwargs) -> Dict:
        combined_params = base_params.copy()
        combined_params.update(kwargs)
        return {k: v for k, v in combined_params.items() if v is not None}
    def _call_api(self, url: str, method: str = 'GET', params: Dict = None, data: Dict = None) -> Union[Dict, None]:
        headers = {
            "Authorization": f"Bearer {self.config.access_token}",
            "User-Agent": self.config.USER_AGENT,
            "Referer": self.config.REFERER_DOMAIN
        }
        if method == 'POST':
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            if data:
                data = self._build_api_params(data)
        response = None
        raw_response_text = ""
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params,
                                        timeout=(self.config.DEFAULT_CONNECT_TIMEOUT, self.config.DEFAULT_READ_TIMEOUT))
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=data,
                                        timeout=(self.config.DEFAULT_CONNECT_TIMEOUT, self.config.DEFAULT_READ_TIMEOUT))
            else:
                logging.error(f"Unsupported HTTP method: {method}")
                return None
            raw_response_text = response.text
            response.raise_for_status()
            if not raw_response_text.strip():
                logging.error(f"Error: Received empty response body from {url}.")
                return None
            result = response.json()
            if logging.root.level <= logging.DEBUG:
                logging.debug(f"Full API response JSON ({url}): {json.dumps(result, indent=4, ensure_ascii=False)}")
            return result
        except requests.exceptions.Timeout:
            logging.warning(f"Request to {url} timed out.")
            return None
        except requests.exceptions.RequestException as e:
            logging.warning(f"Network or request error during call to {url}: {e}")
            return None
        except json.JSONDecodeError:
            logging.error(f"JSON decoding error for {url}. Raw response: >>>{raw_response_text}<<<")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred during call to {url}: {e}")
            return None
    def request(self, url: str, method: str = 'GET', params: Dict = None, data: Dict = None, retry_count: int = 3) -> Union[Dict, None]:
        if self.config.access_token is None:
            if not self._refresh_access_token():
                logging.error("Failed to get access_token, cannot perform API request.")
                return None
        logging.debug(f"当前访问令牌：{self.config.access_token}")
        for attempt in range(retry_count):
            full_url_to_log = url
            if method == 'GET' and params:
                cleaned_params = self._build_api_params(params)
                encoded_params = urlencode({k: str(v) for k in sorted(cleaned_params.keys()) for v in [cleaned_params[k]]})
                full_url_to_log = f"{url}?{encoded_params}"
            logging.debug(f"Request: {method} {full_url_to_log}, Attempt {attempt + 1}/{retry_count}")
            time.sleep(0.1 * attempt)
            result = self._rate_limited_call(self._call_api, url, method, params, data)
            if result is None:
                if attempt < retry_count - 1:
                    logging.warning(f"Attempt {attempt + 1} failed, retrying...")
                    continue
                else:
                    logging.error(f"API request to {url} failed after {retry_count} attempts due to call_api error.")
                    return None
            if result.get("state"):
                return result
            else:
                error_message = result.get('message', 'Unknown API error')
                logging.error(f"115 API error {url}: Message: {result}.")
                if "access_token" in error_message and self._refresh_access_token():
                    logging.warning("access_token validation failed, attempting to re-read token.txt and retry...")
                    continue
                elif attempt < retry_count - 1:
                    logging.warning(f"API returned error, retrying (non-token error, or refresh failed)...")
                    continue
                else:
                    logging.error(f"API request to {url} failed after {retry_count} attempts due to API error state.")
                    return result
        logging.error(f"API request to {url} failed after {retry_count} attempts.")
        return None
    def fetch_files_in_directory_page(self, cid: str, limit: int = 10, offset: int = 0, **kwargs) -> Tuple[List[Dict], int]:
        params = self._build_api_params({"cid": cid, "limit": limit, "offset": offset}, **kwargs)
        logging.debug(f"Calling fetch_files_in_directory_page with params: {params}")
        api_response = self.request(self.config.FILE_LIST_API_URL, 'GET', params)
        if api_response and isinstance(api_response.get("data"), list):
            total_count = api_response.get("count", 0)
            logging.debug(f"Successfully retrieved {len(api_response['data'])} items, offset {offset} (request limit: {limit}). Total items: {total_count}.")
            return api_response["data"], total_count
        else:
            logging.warning(f"Failed to get items for directory ID {cid}, offset {offset}, or returned empty data.")
            return [], 0
    def _fetch_all_items_general(self, fetch_function: callable, base_fetch_kwargs: Dict, total_count: int, page_size: int, main_id_param_name: str = None) -> List[Dict]:
        if total_count == 0:
            return []
        if not main_id_param_name or main_id_param_name not in base_fetch_kwargs:
            logging.error(f"Missing or invalid 'main_id_param_name'... Cannot perform bulk fetch.")
            return []
        logging.debug(f"Starting fetching of all items (Total: {total_count}, Page Size: {page_size})")
        all_items = []
        main_id_value = base_fetch_kwargs.get(main_id_param_name)
        cleaned_kwargs = {k: v for k, v in base_fetch_kwargs.items() if k != main_id_param_name}
        offsets_to_fetch = []
        actual_total_to_fetch = min(total_count, self.config.MAX_SEARCH_EXPLORE_COUNT if fetch_function == self.search_files else total_count)
        for offset in range(0, actual_total_to_fetch, page_size):
            offsets_to_fetch.append(offset)
        if not offsets_to_fetch and actual_total_to_fetch > 0:
            offsets_to_fetch.append(0)
        # === 使用统一并发函数 ===
        fetch_args_list = []
        for offset in offsets_to_fetch:
            page_kwargs = cleaned_kwargs.copy()
            page_kwargs['limit'] = page_size
            page_kwargs['offset'] = offset
            fetch_args_list.append({main_id_param_name: main_id_value, **page_kwargs})
        results = self._fetch_concurrent_pages(fetch_function, fetch_args_list)
        # results 是 [(items, count), ...] 的列表
        results_with_offset = [(offsets_to_fetch[i], res[0] if res else []) for i, res in enumerate(results)]
        results_with_offset.sort(key=lambda x: x[0])
        for page_offset, page_items in results_with_offset:
            if page_items:
                all_items.extend(page_items)
                logging.debug(f"Processing results from offset {page_offset}, total items fetched so far: {len(all_items)}.")
            else:
                logging.warning(f"Failed to get items for offset {page_offset}, or returned empty data.")
        logging.info(f"General fetching of all items completed, fetched {len(all_items)} items.")
        return all_items
    def search_files(self, search_value: str, limit: int = 10, offset: int = 0, **kwargs) -> Tuple[List[Dict], int]:
        logging.debug(f"Searching for keyword: '{search_value}', fetching {limit} items from offset {offset}.")
        params = self._build_api_params({"search_value": search_value, "limit": limit, "offset": offset}, **kwargs)
        logging.debug(f"Calling search_files with params: {params}")
        result = self.request(self.config.SEARCH_API_URL, 'GET', params)
        if result and isinstance(result.get("data"), list):
            total_count = result.get("count", 0)
            logging.debug(f"Successfully retrieved {len(result['data'])} items, offset {offset} (request limit: {limit}).")
            return result["data"], total_count
        else:
            logging.warning(f"Search for keyword '{search_value}' at offset {offset} failed or returned empty data.")
            return [], 0
    def get_download_link_details(self, file_info: Dict) -> Tuple[Union[str, None], Union[str, None], Union[str, None]]:
        file_name = _get_item_attribute(file_info, "fn", "file_name", default_value="Unknown File")
        pick_code = _get_item_attribute(file_info, "pc", "pick_code")
        # 如果是文件夹，跳过
        if is_item_folder(file_info):
            logging.info(f"Skipping folder: {file_name} (it's a directory, no direct download link).")
            return None, None, f"Skipping folder: {file_name}"
        # 关键修复：允许仅通过 pick_code 下载（不要求 fid）
        if not pick_code:
            logging.warning(f"Missing pick_code, cannot get download link. Skipping file: {file_name}")
            return None, None, f"Incomplete file information: {file_name}"
        # 构造请求数据（只需要 pick_code）
        post_data = self._build_api_params({"pick_code": pick_code})
        result = self.request(self.config.DOWNLOAD_API_URL, 'POST', data=post_data)
        if result:
            data_payload = result.get('data')
            # 115 的 downurl 返回结构：{ "e2v0x9z1msseozlo9": { "url": { "url": "https://..." } } }
            if isinstance(data_payload, dict):
                # 直接遍历所有 key（通常是 pick_code），找 url
                for pc_key, pc_data in data_payload.items():
                    if isinstance(pc_data, dict) and 'url' in pc_data:
                        url_obj = pc_data['url']
                        if isinstance(url_obj, dict) and 'url' in url_obj and url_obj['url']:
                            download_url = url_obj['url']
                            file_name = f'{pick_code}_{pc_data['file_name']}'
                            logging.debug(f"Successfully retrieved download link for '{file_name}'.")
                            return download_url, file_name, None
                logging.warning(f"API response 'data' has no valid url field for pick_code '{pick_code}'.")
                return None, None, f"Could not parse download link: {file_name}"
            else:
                logging.warning(f"API response 'data' is not a dict. Raw: {data_payload}")
                return None, None, f"API response format error: {file_name}"
        return None, None, f"Failed to get download link for '{file_name}'"
    def move_files(self, file_ids: List[str], to_cid: str) -> bool:
        if not file_ids:
            logging.warning("No file IDs provided for move operation.")
            return False
        if not to_cid:
            logging.error("Target CID (to_cid) is missing for move operation.")
            return False
        file_ids_str = ",".join(file_ids)
        logging.debug(f"Attempting to move files {file_ids_str} to directory {to_cid}.")
        post_data = self._build_api_params({
            "file_ids": file_ids_str,
            "to_cid": to_cid
        })
        result = self.request(self.config.MOVE_API_URL, 'POST', data=post_data)
        if result and result.get("state"):
            logging.info(f"Successfully moved files {file_ids_str} to {to_cid}.")
            return True
        else:
            error_message = result.get('message', 'Unknown error') if result else "API request failed"
            logging.error(f"Failed to move files {file_ids_str} to {to_cid}: {error_message}")
            return False
    def get_item_details(self, file_or_folder_id: str) -> Union[Dict, None]:
        logging.debug(f"Getting details for file/folder ID: '{file_or_folder_id}'...")
        params = self._build_api_params({"file_id": file_or_folder_id})
        result = self.request(self.config.GET_FOLDER_INFO_API_URL, 'GET', params=params)
        if result and result.get("state") and isinstance(result.get("data"), dict):
            data = result["data"]
            logging.debug(f"Successfully retrieved details for file/folder ID: '{file_or_folder_id}'.")
            return data
        else:
            error_message = result.get('message', 'Unknown error') if result else "API request failed"
            logging.warning(f"Failed to get details for file/folder ID: '{file_or_folder_id}': {error_message}")
            return None
    # ============ 重写：并发批量获取详情 ============
    def get_items_details_batch(self, file_ids: List[str]) -> Dict[str, Dict]:
        """
        并发获取多个 file_id 的详情，返回 {file_id: details_dict}
        使用统一并发函数
        """
        if not file_ids:
            return {}
        # 构造参数列表
        fetch_args_list = [{"file_or_folder_id": fid} for fid in file_ids]
        results = self._fetch_concurrent_pages(self.get_item_details, fetch_args_list)
        return {fid: detail for fid, detail in zip(file_ids, results) if detail is not None}
    def create_folder(self, parent_id: str, folder_name: str) -> Tuple[Union[str, None], Union[str, None], Union[str, None]]:
        logging.debug(f"Attempting to create folder: '{folder_name}' in parent directory '{parent_id}'...")
        post_data = {
            "pid": parent_id,
            "file_name": folder_name
        }
        result = self.request(self.config.ADD_FOLDER_API_URL, 'POST', data=post_data)
        if result and result.get("state"):
            data = result.get("data")
            if isinstance(data, dict):
                new_folder_name = _get_item_attribute(data, "file_name", default_value="Unknown folder")
                new_folder_id = _get_item_attribute(data, "file_id")
                if new_folder_name and new_folder_id:
                    logging.debug(f"Successfully created folder: '{new_folder_name}' (ID: {new_folder_id}).")
                    return new_folder_id, new_folder_name, None
                else:
                    logging.error(f"Folder creation succeeded, but new folder name or ID is missing from API response. Response data: {data}")
                    return None, None, "API response missing new folder information"
            else:
                logging.error(f"Folder creation succeeded, but API response 'data' field is in an incorrect format. Response: {result}")
                return None, None, "API response format error"
        else:
            error_message = result.get('message', 'Unknown error') if result else "API request failed"
            logging.error(f"Failed to create folder '{folder_name}': {error_message}")
            return None, None, error_message
    def rename_file_or_folder(self, file_id: str, new_file_name: str) -> Tuple[bool, Union[str, None], Union[str, None]]:
        logging.debug(f"Attempting to rename file/folder ID '{file_id}' to: '{new_file_name}'...")
        post_data = {
            "file_id": file_id,
            "file_name": new_file_name
        }
        result = self.request(self.config.UPDATE_FILE_API_URL, 'POST', data=post_data)
        if result and result.get("state"):
            data = result.get("data")
            if isinstance(data, dict):
                updated_file_name = _get_item_attribute(data, "file_name", default_value=new_file_name)
                if updated_file_name:
                    logging.debug(f"Successfully renamed file/folder ID '{file_id}' to '{updated_file_name}'.")
                    return True, updated_file_name, None
                else:
                    logging.error(f"Rename succeeded, but updated file name is missing from API response. Response data: {data}")
                    return False, None, "API response missing updated name"
            else:
                logging.error(f"Rename succeeded, but API response 'data' field is in an incorrect format. Response: {result}")
                return False, None, "API response format error"
        else:
            error_message = result.get('message', 'Unknown error') if result else "API request failed"
            logging.error(f"Failed to rename file/folder ID '{file_id}': {error_message}")
            return False, None, error_message
    def delete_files_or_folders(self, file_ids: List[str], parent_id: Union[str, None] = None) -> Tuple[bool, Union[str, None]]:
        if not file_ids:
            logging.warning("No file IDs provided for delete operation.")
            return False, "No file IDs provided"
        file_ids_str = ",".join(file_ids)
        logging.debug(f"Attempting to delete files/folders: {file_ids_str}")
        post_data = {
            "file_ids": file_ids_str
        }
        if parent_id:
            post_data["parent_id"] = parent_id
        result = self.request(self.config.DELETE_FILE_API_URL, 'POST', data=post_data)
        if result and result.get("state"):
            logging.info(f"Successfully deleted files/folders: {file_ids_str}.")
            return True, None
        else:
            error_message = result.get('message', 'Unknown error') if result else "API request failed"
            logging.error(f"Failed to delete files/folders {file_ids_str}: {error_message}")
            return False, error_message
    def add_cloud_download_task(self, urls: str, wp_path_id: str = '0') -> Tuple[bool, str, Union[List[Dict], None]]:
        logging.info(f"Adding cloud download tasks to directory '{wp_path_id}'...")
        post_data = {
            "urls": urls,
            "wp_path_id": wp_path_id
        }
        result = self.request(self.config.CLOUD_DOWNLOAD_API_URL, 'POST', data=post_data)
        if result and result.get("state"):
            data = result.get("data", [])
            successful_tasks = [task for task in data if task.get("state")]
            failed_tasks = [task for task in data if not task.get("state")]
            if failed_tasks:
                for task in failed_tasks:
                    logging.error(f"Cloud download task failed: URL: {task.get('url', 'Unknown')}, Message: {task.get('message', 'Unknown error')}")
                return False, f"Some or all tasks failed, please check logs for details.", data
            return True, "All cloud download tasks successfully added.", data
        else:
            error_message = result.get('message', 'Unknown error') if result else "API request failed"
            logging.error(f"Failed to add cloud download tasks: {error_message}")
            return False, error_message, None
    def download_file(self, url: str, filename: str, save_path: str) -> Tuple[bool, int, Union[str, None]]:
        safe_filename = _get_safe_filename(filename, self.config)
        full_path = os.path.join(save_path, safe_filename)
        os.makedirs(save_path, exist_ok=True)
        logging.info(f"Download:'{full_path}'")
        try:
            download_headers = {
                "User-Agent": self.config.USER_AGENT,
                "Referer": self.config.REFERER_DOMAIN
            }
            with requests.get(url, stream=True, timeout=(self.config.DEFAULT_CONNECT_TIMEOUT, self.config.DEFAULT_READ_TIMEOUT), headers=download_headers) as r:
                r.raise_for_status()
                total_size_response_header = int(r.headers.get('content-length', 0))
                downloaded_size = 0
                start_time = time.time()
                with open(full_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)
                end_time = time.time()
                duration = end_time - start_time
                speed = downloaded_size / duration / (1024 * 1024) if duration > 0 else 0
                logging.debug(f"File '{safe_filename}' downloaded. Size: {downloaded_size / (1024*1024):.2f} MB. Time: {duration:.2f} s. Average speed: {speed:.2f} MB/s.")
                return True, downloaded_size, None
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to download file '{safe_filename}': Network or request error: {e}")
            if os.path.exists(full_path): os.remove(full_path)
            return False, 0, f"Download failed: {safe_filename} - Network error: {e}"
        except Exception as e:
            logging.error(f"An unexpected error occurred while downloading file '{safe_filename}': {e}")
            if os.path.exists(full_path): os.remove(full_path)
            return False, 0, f"Download failed: {safe_filename} - Unexpected error: {e}"
class TokenManager:
    def __init__(self, config: AppConfig):
        self.config = config
    def _generate_code_verifier(self, length=128):
        length = secrets.choice(range(43, 129))
        allowed_chars = string.ascii_letters + string.digits + '-._~'
        return ''.join(secrets.choice(allowed_chars) for _ in range(length))
    def _generate_code_challenge(self, code_verifier):
        sha256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(sha256).rstrip(b'=').decode('ascii')
    def _execute_shell_command(self, command: list) -> tuple[int, str, str]:
        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8')
            if process.returncode != 0:
                logging.error(f"rclone 命令失败。命令: {' '.join(command)}, 返回码: {process.returncode}, 错误输出: {process.stderr.strip()}")
            return process.returncode, process.stdout, process.stderr
        except FileNotFoundError:
            logging.error(f"错误: 未找到命令 '{command[0]}'. 请确保 rclone 已安装并存在于你的 PATH 中。")
            return 127, "", "Command not found."
        except Exception as e:
            logging.error(f"执行命令时发生异常: {e}")
            return 1, "", str(e)
    def _save_token_data_to_rclone(self, token_data: dict, api_status_code: int = 0) -> bool:
        json_string_data = json.dumps({
            "timestamp": int(time.time()),
            "state": 1, "code": api_status_code, "message": "",
            "data": {
                "access_token": token_data.get("access_token", ""),
                "refresh_token": token_data.get("refresh_token", ""),
                "expires_in": token_data.get("expires_in", 7200),
                "user_id": token_data.get("user_id", "")
            },
            "error": "", "errno": api_status_code
        }, indent=4, ensure_ascii=False)
        try:
            new_token = 'temp_token.txt'
            with open(new_token, mode='w', encoding='utf-8') as f:
                f.write(json_string_data)
            subprocess.run(["rclone", "deletefile", self.config.RCLONE_TOKEN_FULL_PATH])
            subprocess.run(["rclone", "moveto", new_token, self.config.RCLONE_TOKEN_FULL_PATH])
        except Exception as e:
            logging.error(f"保存令牌时发生意外错误: {e}")
            return False
    def _get_new_tokens_via_device_code(self) -> dict | None:
        code_verifier = self._generate_code_verifier()
        code_challenge = self._generate_code_challenge(code_verifier)
        auth_data = None
        try:
            response = requests.post(
                self.config.AUTH_DEVICE_CODE_URL,
                data={"client_id": self.config.CLIENT_ID, "code_challenge": code_challenge, "code_challenge_method": "sha256"},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            auth_data = response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"请求设备码 API 失败: {e}")
            return None
        except json.JSONDecodeError:
            logging.error(f"未能解析设备码 API 响应。")
            return None
        if not auth_data or auth_data.get("code") != 0 or "data" not in auth_data:
            logging.error(f"未能获取设备码。响应: {auth_data}")
            return None
        uid = auth_data['data'].get('uid')
        qrcode_content = auth_data['data'].get('qrcode')
        time_val = auth_data['data'].get('time')
        sign = auth_data['data'].get('sign')
        if not all([uid, qrcode_content, time_val, sign]):
            logging.error("设备码响应缺少关键数据。")
            return None
        print("\n请使用 115 客户端扫描下方二维码进行授权:")
        qrcode_terminal.draw(qrcode_content)
        print(f"QR 码内容: {qrcode_content}")
        while True:
            try:
                status_resp = requests.get(
                    self.config.QRCODE_STATUS_URL,
                    params={"uid": uid, "time": time_val, "sign": sign}
                )
                status_resp.raise_for_status()
                status_data = status_resp.json()
                if status_data.get('data', {}).get('status') == 2:
                    break
                time.sleep(5)
            except requests.exceptions.RequestException as e:
                logging.error(f"轮询 QR 码状态 API 失败: {e}")
                return None
            except json.JSONDecodeError:
                logging.error(f"未能解析 QR 码状态 API 响应。")
                return None
        final_token_data = None
        try:
            token_resp = requests.post(
                self.config.DEVICE_CODE_TO_TOKEN_URL,
                data={"uid": uid, "code_verifier": code_verifier},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            token_resp.raise_for_status()
            final_token_data = token_resp.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"交换设备码获取令牌 API 失败: {e}")
            return None
        except json.JSONDecodeError:
            logging.error(f"未能解析最终令牌 API 响应。")
            return None
        if final_token_data and final_token_data.get("code") == 0 and "data" in final_token_data:
            logging.debug(f"设备码获取的完整token:{final_token_data}")
            return final_token_data["data"]
        else:
            logging.error(f"未能获取初始令牌。响应: {final_token_data}")
            return None
    def _load_token_data_from_remote(self) -> dict | None:
        command_cat = ["rclone", "cat", self.config.RCLONE_TOKEN_FULL_PATH]
        return_code_cat, stdout_cat, stderr_cat = self._execute_shell_command(command_cat)
        if return_code_cat == 0 and stdout_cat:
            try:
                token_container = json.loads(stdout_cat)
                if isinstance(token_container, dict) and "data" in token_container:
                    return token_container["data"]
                else:
                    logging.warning(f"警告: 远程文件 '{self.config.RCLONE_TOKEN_FULL_PATH}' 内容格式不正确（缺少 'data' 键或不是字典）。")
                    return None
            except json.JSONDecodeError:
                logging.warning(f"警告: 远程文件 '{self.config.RCLONE_TOKEN_FULL_PATH}' 内容不是有效的 JSON。")
                return None
            except Exception as e:
                logging.warning(f"警告: 解析远程令牌文件时发生未知错误: {e}。")
                return None
        else:
            logging.warning(f"警告: 未能读取远程令牌文件 '{self.config.RCLONE_TOKEN_FULL_PATH}' (返回码: {return_code_cat}, 错误: {stderr_cat.strip()})。")
            return None
    def _refresh_access_token_from_api(self, refresh_token_value: str) -> dict | None:
        response = None
        try:
            response = requests.post(
                self.config.REFRESH_TOKEN_URL,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"refresh_token": refresh_token_value}
            )
            response.raise_for_status()
            if not response.text or not response.text.strip():
                logging.error(f"错误: 刷新 API 收到空响应体。")
                return None
            result = response.json()
            if result.get("code") == 0 and "data" in result:
                return result["data"]
            else:
                logging.error(f"令牌刷新失败。错误信息: {result.get('message', '未知错误')}, 完整响应: {result}")
                return None
        except requests.exceptions.RequestException as e:
            logging.error(f"令牌刷新 API 调用失败: {e}")
            return None
        except json.JSONDecodeError:
            logging.error(f"未能解析刷新 API 响应。")
            return None
    def get_access_token_from_file(self) -> dict | None:
        logging.debug("尝试从远程文件直接读取令牌。")
        try:
            loaded_data = self._load_token_data_from_remote()
            if loaded_data and loaded_data.get("access_token"):
                logging.debug("成功从远程文件读取到令牌数据。")
                return loaded_data.get("access_token")
            else:
                x = self.authenticate_with_device_code()
                return x
        except Exception as e:
            logging.error(f"错误：{e}")
            return None
    def refresh_and_get_new_token(self) -> dict | None:
        loaded_data = self._load_token_data_from_remote()
        new_token_data = self._refresh_access_token_from_api(loaded_data.get("refresh_token"))
        if new_token_data:
            self._save_token_data_to_rclone(new_token_data, api_status_code=0)
            return new_token_data.get("access_token")
        else:
            logging.error("Refresh Token 刷新失败。")
            x = self.authenticate_with_device_code()
            return x
    def authenticate_with_device_code(self) -> dict | None:
        logging.info("执行新的设备码认证流程。")
        new_token_data = self._get_new_tokens_via_device_code()
        if new_token_data:
            logging.info("设备码认证成功，正在保存到远程文件。")
            self._save_token_data_to_rclone(new_token_data, api_status_code=0)
            return new_token_data.get("access_token")
        else:
            logging.error("设备码认证最终失败。")
            return None
class Uploader:
    CMD_RENDER_NEEDED = "render_needed"
    CMD_CONTINUE_INPUT = "continue_input"
    CMD_EXIT = "exit"
    def __init__(self, config: AppConfig, api_service: ApiService, initial_cid: str = '0'):
        self.config = config
        self.api_service = api_service
        self.current_folder_id = initial_cid
        self._last_fetched_params_hash = None
        self.current_offset = 0
        self.showing_all_items = False
    @staticmethod
    def _get_item_attribute(item: dict, *keys: str, default_value: Any = None) -> Any:
        for key in keys:
            if key in item:
                return item[key]
        return default_value
    @staticmethod
    def is_item_folder(item: dict) -> bool:
        file_category = Uploader._get_item_attribute(item, "fc", "file_category")
        return (file_category == "0")
    @staticmethod
    def _build_api_params(base_params: Dict, **kwargs) -> Dict:
        combined_params = base_params.copy()
        combined_params.update(kwargs)
        return {k: v for k, v in combined_params.items() if v is not None}
    @staticmethod
    def format_bytes_to_human_readable(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    def calculate_file_hashes(self, filepath: str) -> Tuple[Union[str, None], Union[str, None], int]:
        try:
            file_size = os.path.getsize(filepath)
            sha1_hasher = hashlib.sha1()
            pre_sha1_hasher = hashlib.sha1()
            PREID_BLOCK_SIZE = 131072
            with open(filepath, 'rb') as f:
                preid_data = f.read(PREID_BLOCK_SIZE)
                pre_sha1_hasher.update(preid_data)
                f.seek(0)
                for chunk in iter(lambda: f.read(4096 * 1024), b''):
                    sha1_hasher.update(chunk)
            return sha1_hasher.hexdigest(), pre_sha1_hasher.hexdigest(), file_size
        except Exception as e:
            logging.error(f"Error calculating file hashes for {filepath}: {e}")
            return None, None, 0
    def calculate_range_sha1(self, filepath: str, byte_range_str: str) -> Union[str, None]:
        try:
            parts = byte_range_str.split('-')
            if len(parts) != 2:
                logging.error(f"Invalid byte range string format: {byte_range_str}")
                return None
            start_byte = int(parts[0])
            end_byte = int(parts[1])
            if start_byte > end_byte:
                logging.error(f"Invalid byte range: start > end in {byte_range_str}")
                return None
            with open(filepath, 'rb') as f:
                f.seek(start_byte)
                bytes_to_read = end_byte - start_byte + 1
                data = f.read(bytes_to_read)
                return hashlib.sha1(data).hexdigest().upper()
        except (ValueError, IndexError) as e:
            logging.error(f"Error parsing byte range string '{byte_range_str}': {e}")
            return None
        except Exception as e:
            logging.error(f"Error calculating range SHA1 for {filepath}, range {byte_range_str}: {e}")
            return None
    @staticmethod
    def _to_base64(s: Union[bytes, str], /) -> str:
        if isinstance(s, str):
            s = s.encode("utf-8")
        return base64.b64encode(s).decode("ascii")
    @staticmethod
    def _sign_oss_request(
        access_key_secret: str,
        method: str,
        bucket: str,
        object_key: str,
        headers: Dict[str, str],
        query_params: Dict[str, Union[str, None]] = None,
        content_md5: str = "",
        content_type: str = ""
    ) -> str:
        canonicalized_oss_headers = []
        for k, v in sorted(headers.items()):
            k_lower = k.lower()
            if k_lower.startswith('x-oss-'):
                canonicalized_oss_headers.append(f"{k_lower}:{v.strip()}")
        canonicalized_oss_headers_str = "\n".join(canonicalized_oss_headers)
        canonicalized_resource = f"/{bucket}/{object_key}"
        if query_params:
            sorted_params = sorted(query_params.items())
            param_strings = []
            for k, v in sorted_params:
                if v is not None:
                    param_strings.append(f"{k}={v}")
                else:
                    param_strings.append(f"{k}")
            canonicalized_resource += "?" + "&".join(param_strings)
        date_header = headers.get("x-oss-date") or headers.get("date")
        if not date_header:
            date_header = formatdate(usegmt=True)
            headers["Date"] = date_header
        string_to_sign = (
            f"{method}\n"
            f"{content_md5}\n"
            f"{content_type}\n"
            f"{date_header}\n"
            f"{canonicalized_oss_headers_str}\n"
            f"{canonicalized_resource}"
        )
        h = hmac.new(access_key_secret.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1)
        signature = base64.b64encode(h.digest()).decode('utf-8')
        return signature
    def _do_oss_rest_request(
        self,
        method: str,
        oss_credentials: Dict,
        bucket_name: str,
        object_key: str,
        headers: Dict[str, str],
        query_params: Dict[str, Union[str, None]] = None,
        data: Any = None,
        content_type: str = "application/octet-stream"
    ) -> requests.Response:
        original_credentials = oss_credentials
        for attempt in range(self.config.UPLOAD_RETRY_COUNT):
            try:
                access_key_id = original_credentials['AccessKeyId']
                access_key_secret = original_credentials['AccessKeySecret']
                security_token = original_credentials['SecurityToken']
                endpoint = original_credentials['endpoint']
                protocol = "https://"
                if endpoint.startswith('http://'):
                    protocol = "http://"
                    endpoint_domain = endpoint[len("http://"):]
                elif endpoint.startswith('https://'):
                    endpoint_domain = endpoint[len("https://"):]
                else:
                    endpoint_domain = endpoint
                request_host = f"{bucket_name}.{endpoint_domain}"
                full_url = f"{protocol}{request_host}/{quote(object_key)}"
                if query_params:
                    encoded_params = urlencode({k: v for k, v in query_params.items() if v is not None}, doseq=True)
                    for k, v in query_params.items():
                        if v is None:
                            encoded_params += f"&{k}" if encoded_params else k
                    if encoded_params:
                        full_url += f"?{encoded_params}"
                request_headers = headers.copy()
                request_headers["Host"] = request_host
                request_headers["x-oss-security-token"] = security_token
                content_md5 = ""
                if data and isinstance(data, bytes):
                    content_md5 = base64.b64encode(hashlib.md5(data).digest()).decode('utf-8')
                    request_headers["Content-MD5"] = content_md5
                elif 'Content-MD5' in request_headers:
                    content_md5 = request_headers['Content-MD5']
                request_headers["Content-Type"] = content_type
                signature = self._sign_oss_request(
                    access_key_secret=access_key_secret,
                    method=method.upper(),
                    bucket=bucket_name,
                    object_key=object_key,
                    headers=request_headers,
                    query_params=query_params,
                    content_md5=content_md5,
                    content_type=content_type
                )
                request_headers["Authorization"] = f"OSS {access_key_id}:{signature}"
                logging.debug(f"Attempt {attempt + 1}/{self.config.UPLOAD_RETRY_COUNT}: Sending OSS request: {method} {full_url}")
                session = requests.Session()
                try:
                    response = session.request(
                        method.upper(),
                        full_url,
                        headers=request_headers,
                        data=data,
                        timeout=(self.config.DEFAULT_CONNECT_TIMEOUT, self.config.DEFAULT_READ_TIMEOUT)
                    )
                    if response.status_code == 403:
                        error_text = response.text
                        if 'SecurityTokenExpired' in error_text or 'ExpiredToken' in error_text or 'InvalidAccessKeyId' in error_text:
                            logging.warning(f"OSS credentials expired or invalid (attempt {attempt + 1}). Refreshing credentials...")
                            new_oss_credentials = self.get_upload_token()
                            if new_oss_credentials:
                                original_credentials.clear()
                                original_credentials.update(new_oss_credentials)
                                logging.info("OSS credentials refreshed successfully, retrying request...")
                                time.sleep(2)
                                continue
                            else:
                                logging.error("Failed to refresh OSS credentials.")
                                response.raise_for_status()
                    response.raise_for_status()
                    return response
                finally:
                    session.close()
            except requests.exceptions.HTTPError as e:
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 403:
                        error_text = e.response.text
                        if 'SecurityTokenExpired' in error_text or 'ExpiredToken' in error_text or 'InvalidAccessKeyId' in error_text:
                            logging.warning(f"OSS credentials expired or invalid (attempt {attempt + 1}). Refreshing credentials...")
                            new_oss_credentials = self.get_upload_token()
                            if new_oss_credentials:
                                original_credentials.clear()
                                original_credentials.update(new_oss_credentials)
                                logging.info("OSS credentials refreshed successfully, retrying request...")
                                if attempt < self.config.UPLOAD_RETRY_COUNT - 1:
                                    time.sleep(2)
                                    continue
                            else:
                                logging.error("Failed to refresh OSS credentials.")
                logging.warning(f"HTTP error during OSS request (Attempt {attempt + 1}/{self.config.UPLOAD_RETRY_COUNT}): {e}")
                if attempt < self.config.UPLOAD_RETRY_COUNT - 1:
                    logging.info(f"Retrying in {self.config.UPLOAD_RETRY_DELAY_SECONDS} seconds...")
                    time.sleep(self.config.UPLOAD_RETRY_DELAY_SECONDS)
                else:
                    logging.error("OSS request failed after all retries.")
                    raise
            except requests.exceptions.RequestException as e:
                logging.warning(f"Network error during OSS request (Attempt {attempt + 1}/{self.config.UPLOAD_RETRY_COUNT}): {e}")
                if attempt < self.config.UPLOAD_RETRY_COUNT - 1:
                    logging.info(f"Retrying in {self.config.UPLOAD_RETRY_DELAY_SECONDS} seconds...")
                    time.sleep(self.config.UPLOAD_RETRY_DELAY_SECONDS)
                else:
                    logging.error("OSS request failed after all retries.")
                    raise
        logging.error("OSS request failed after all retries.")
        raise Exception("OSS request failed after all retries")
    def _oss_multipart_initiate(
        self,
        oss_credentials: Dict,
        bucket_name: str,
        object_key: str,
    ) -> str:
        logging.debug(f"Initiating multipart upload for {object_key}")
        for attempt in range(self.config.UPLOAD_RETRY_COUNT):
            try:
                headers = {}
                query_params = {'uploads': None, 'sequential': '1'}
                response = self._do_oss_rest_request(
                    method='POST',
                    oss_credentials=oss_credentials,
                    bucket_name=bucket_name,
                    object_key=object_key,
                    headers=headers,
                    query_params=query_params,
                    content_type="application/xml"
                )
                from xml.etree import ElementTree as ET
                root = ET.fromstring(response.text)
                upload_id_element = root.find('UploadId')
                if upload_id_element is None or not upload_id_element.text:
                    raise Exception(f"Failed to get UploadId from initiate response: {response.text}")
                return upload_id_element.text
            except requests.exceptions.HTTPError as e:
                if attempt < self.config.UPLOAD_RETRY_COUNT - 1 and hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 403:
                        logging.warning(f"Initiate multipart upload failed due to token expiry (attempt {attempt + 1}).")
                        time.sleep(self.config.UPLOAD_RETRY_DELAY_SECONDS)
                        continue
                raise
    def _oss_multipart_upload_part(
        self,
        oss_credentials: Dict,
        bucket_name: str,
        object_key: str,
        upload_id: str,
        part_number: int,
        part_data: bytes,
    ) -> str:
        logging.debug(f"Uploading part {part_number} for {object_key}")
        headers = {}
        query_params = {'uploadId': upload_id, 'partNumber': str(part_number)}
        content_md5_part = base64.b64encode(hashlib.md5(part_data).digest()).decode('utf-8')
        headers["Content-MD5"] = content_md5_part
        response = self._do_oss_rest_request(
            method='PUT',
            oss_credentials=oss_credentials,
            bucket_name=bucket_name,
            object_key=object_key,
            headers=headers,
            query_params=query_params,
            data=part_data,
            content_type="application/octet-stream"
        )
        etag = response.headers.get('ETag', '').strip('"')
        if not etag:
            raise Exception(f"Missing ETag from part {part_number} upload response for {object_key}")
        return etag
    def _oss_multipart_complete(
        self,
        oss_credentials: Dict,
        bucket_name: str,
        object_key: str,
        upload_id: str,
        parts_info: List[Dict],
        callback_base64: str,
        callback_var_base64: str,
    ) -> Dict:
        logging.debug(f"Completing multipart upload for {object_key}")
        for attempt in range(self.config.UPLOAD_RETRY_COUNT):
            try:
                headers = {
                    "x-oss-callback": callback_base64,
                    "x-oss-callback-var": callback_var_base64,
                }
                query_params = {'uploadId': upload_id}
                parts_xml = "".join([
                    f"<Part><PartNumber>{p['PartNumber']}</PartNumber><ETag>{p['ETag']}</ETag></Part>"
                    for p in parts_info
                ])
                complete_body_xml = f"<CompleteMultipartUpload>{parts_xml}</CompleteMultipartUpload>"
                complete_body_bytes = complete_body_xml.encode('utf-8')
                response = self._do_oss_rest_request(
                    method='POST',
                    oss_credentials=oss_credentials,
                    bucket_name=bucket_name,
                    object_key=object_key,
                    headers=headers,
                    query_params=query_params,
                    data=complete_body_bytes,
                    content_type="application/xml"
                )
                try:
                    return response.json()
                except json.JSONDecodeError:
                    logging.info(f"Complete multipart response is not JSON, treating as success: {response.text}")
                    return {"status": "success", "response_text": response.text}
            except requests.exceptions.RequestException as e:
                logging.error(f"Error while aborting multipart upload {upload_id}: {e}")
    def _oss_multipart_abort(
        self,
        oss_credentials: Dict,
        bucket_name: str,
        object_key: str,
        upload_id: str,
    ) -> bool:
        logging.info(f"Aborting multipart upload {upload_id} for {object_key}")
        headers = {}
        query_params = {'uploadId': upload_id}
        try:
            response = self._do_oss_rest_request(
                method='DELETE',
                oss_credentials=oss_credentials,
                bucket_name=bucket_name,
                object_key=object_key,
                headers=headers,
                query_params=query_params,
                content_type="application/xml"
            )
            if response.status_code == 204 or response.status_code == 404:
                logging.info(f"Multipart upload {upload_id} aborted successfully or already non-existent.")
                return True
            else:
                logging.error(f"Failed to abort multipart upload {upload_id}. Status: {response.status_code}, Response: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Error while aborting multipart upload {upload_id}: {e}")
            return False
    def upload_to_object_storage(
        self,
        file_path: str,
        bucket_name: str,
        object_id: str,
        file_size: int,
        file_sha1: str,
        oss_credentials_for_upload: Dict,
        callback_info_json_string: str,
        callback_var_json_string: str
    ) -> bool:
        logging.info(f"Starting file upload '{os.path.basename(file_path)}' to OSS via REST API...")
        if not all([oss_credentials_for_upload.get('endpoint'),
                    oss_credentials_for_upload.get('AccessKeyId'),
                    oss_credentials_for_upload.get('AccessKeySecret'),
                    oss_credentials_for_upload.get('SecurityToken')]):
            logging.error("Missing required OSS credentials.")
            return False
        object_key = object_id.lstrip('/')
        callback_base64 = self._to_base64(callback_info_json_string)
        callback_var_base64 = self._to_base64(callback_var_json_string)
        upload_success = False
        upload_id = None
        try:
            if file_size < self.config.MULTIPART_UPLOAD_MIN_SIZE:
                logging.info(f"File size {file_size} bytes is less than {self.config.MULTIPART_UPLOAD_MIN_SIZE} bytes. Using single-part upload.")
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                headers = {
                    "x-oss-callback": callback_base64,
                    "x-oss-callback-var": callback_var_base64,
                }
                response = self._do_oss_rest_request(
                    method='PUT',
                    oss_credentials=oss_credentials_for_upload,
                    bucket_name=bucket_name,
                    object_key=object_key,
                    headers=headers,
                    data=file_content,
                    content_type="application/octet-stream"
                )
                if response.status_code == 200:
                    logging.info(f"Single-part upload successful for '{os.path.basename(file_path)}'. Response: {response.text}")
                    upload_success = True
                else:
                    logging.error(f"Single-part upload failed. Status: {response.status_code}, Response: {response.text}")
            else:
                logging.info(f"File size {file_size} bytes is >= {self.config.MULTIPART_UPLOAD_MIN_SIZE} bytes. Using multi-part upload.")
                part_size = self._cal_part_size(file_size)
                parts_info = []
                upload_id = self._oss_multipart_initiate(
                    oss_credentials=oss_credentials_for_upload,
                    bucket_name=bucket_name,
                    object_key=object_key,
                )
                logging.info(f"Multi-part upload initialized, UploadId: {upload_id}")
                part_number = 1
                total_uploaded_bytes = 0
                with open(file_path, 'rb') as f:
                    while True:
                        part_data = f.read(part_size)
                        if not part_data:
                            break
                        etag = self._oss_multipart_upload_part(
                            oss_credentials=oss_credentials_for_upload,
                            bucket_name=bucket_name,
                            object_key=object_key,
                            upload_id=upload_id,
                            part_number=part_number,
                            part_data=part_data,
                        )
                        parts_info.append({"PartNumber": part_number, "ETag": etag})
                        total_uploaded_bytes += len(part_data)
                        sys.stdout.write(f"\rUpload Progress: {total_uploaded_bytes / file_size * 100:.2f}% ({self.format_bytes_to_human_readable(total_uploaded_bytes)}/{self.format_bytes_to_human_readable(file_size)})")
                        sys.stdout.flush()
                        part_number += 1
                sys.stdout.write('\n')
                completion_response = self._oss_multipart_complete(
                    oss_credentials=oss_credentials_for_upload,
                    bucket_name=bucket_name,
                    object_key=object_key,
                    upload_id=upload_id,
                    parts_info=parts_info,
                    callback_base64=callback_base64,
                    callback_var_base64=callback_var_base64,
                )
                logging.info(f"Multipart upload completion response: {completion_response}")
                upload_success = True
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP request error during OSS upload for '{os.path.basename(file_path)}': {e}")
            if e.response is not None:
                logging.error(f"Response status: {e.response.status_code}, body: {e.response.text}")
            upload_success = False
        except Exception as e:
            logging.error(f"An unexpected error occurred during OSS upload for '{os.path.basename(file_path)}': {e}")
            upload_success = False
        finally:
            if not upload_success and upload_id:
                try:
                    self._oss_multipart_abort(
                        oss_credentials=oss_credentials_for_upload,
                        bucket_name=bucket_name,
                        object_key=object_key,
                        upload_id=upload_id,
                    )
                except Exception as abort_error:
                    logging.warning(f"Error during multipart upload abort: {abort_error}")
        return upload_success
    def _cal_part_size(self, file_size: int) -> int:
        MB = 1024 * 1024
        if self.config.MULTIPART_UPLOAD_MIN_SIZE <= file_size < self.config.SMALL_FILE_MAX_SIZE_FOR_5MB_CHUNKS:
            logging.debug(f"File size {self.format_bytes_to_human_readable(file_size)} is between {self.format_bytes_to_human_readable(self.config.MULTIPART_UPLOAD_MIN_SIZE)} and {self.format_bytes_to_human_readable(self.config.SMALL_FILE_MAX_SIZE_FOR_5MB_CHUNKS)}. Using custom part size: {self.format_bytes_to_human_readable(self.config.CUSTOM_CHUNK_SIZE_FOR_SMALL_FILES)}.")
            return self.config.CUSTOM_CHUNK_SIZE_FOR_SMALL_FILES
        elif file_size >= self.config.SMALL_FILE_MAX_SIZE_FOR_5MB_CHUNKS:
            logging.debug(f"File size {self.format_bytes_to_human_readable(file_size)} is >= {self.config.SMALL_FILE_MAX_SIZE_FOR_5MB_CHUNKS}. Using fixed part size: {self.format_bytes_to_human_readable(self.config.LARGE_FILE_FIXED_CHUNK_SIZE)}.")
            return self.config.LARGE_FILE_FIXED_CHUNK_SIZE
        else:
            logging.debug(f"File size {self.format_bytes_to_human_readable(file_size)} is less than multipart upload minimum ({self.format_bytes_to_human_readable(self.config.MULTIPART_UPLOAD_MIN_SIZE)}). Returning default part size (20MB).")
            return 20 * MB
    def get_upload_token(self) -> Union[Dict, None]:
        logging.info("Getting upload credentials.")
        result = self.api_service.request(self.config.GET_UPLOAD_TOKEN_API_URL, 'GET')
        if result and result.get("state") and isinstance(result.get("data"), dict):
            logging.info("Successfully obtained upload credentials.")
            return result["data"]
        else:
            error_message = result.get('message', 'Unknown error') if result else "API request failed"
            logging.error(f"Failed to get upload credentials: {error_message}")
            return None
    def upload_init(
        self,
        file_name: str,
        file_size: int,
        target: str,
        fileid: str,
        preid: str,
        topupload: int = 0,
        sign_key: Union[str, None] = None,
        sign_val: Union[str, None] = None
    ) -> Union[Dict, None]:
        logging.info(f"Initializing upload for file '{file_name}' to '{target}'.")
        post_data = {
            "file_name": file_name,
            "file_size": str(file_size),
            "target": target,
            "fileid": fileid,
            "preid": preid,
            "topupload": str(topupload)
        }
        if sign_key:
            post_data["sign_key"] = sign_key
        if sign_val:
            post_data["sign_val"] = sign_val
        result = self.api_service.request(self.config.UPLOAD_INIT_API_URL, 'POST', data=post_data)
        return result
    def _execute_single_file_upload_task(
        self,
        local_file_path: str,
        target_folder_id: str,
        topupload: int = 0
    ) -> Tuple[bool, str]:
        file_name = os.path.basename(local_file_path)
        for attempt in range(self.config.UPLOAD_RETRY_COUNT):
            logging.info(f"Starting file upload: '{file_name}' (Attempt {attempt + 1}/{self.config.UPLOAD_RETRY_COUNT}).")
            try:
                if not os.path.exists(local_file_path):
                    logging.error(f"Local file does not exist: '{local_file_path}'.")
                    return False, f"File does not exist: {file_name}"
                file_sha1, pre_sha1, file_size = self.calculate_file_hashes(local_file_path)
                if not file_sha1 or not pre_sha1 or file_size is None:
                    return False, f"Failed to calculate file hashes: {file_name}"
                target = f"U_1_{target_folder_id}"
                init_response = self.upload_init(
                    file_name=file_name,
                    file_size=file_size,
                    target=target,
                    fileid=file_sha1,
                    preid=pre_sha1,
                    topupload=topupload,
                )
                if not init_response:
                    raise Exception("Upload initialization API call failed.")
                init_data = init_response.get("data")
                if not init_data:
                    raise Exception("Upload initialization response data is empty.")
                status = init_data.get("status")
                message = init_response.get("message", "Unknown message")
                if status == 2:
                    logging.info(f"File '{file_name}' quick transfer successful! File ID: {init_data.get('file_id')}.")
                    return True, f"Quick transfer successful: {file_name}"
                if status in [6, 7, 8]:
                    logging.warning(f"File '{file_name}' requires secondary authentication. Status: {status}, Message: {message}.")
                    if status == 8:
                        raise Exception(f"Secondary authentication failed with status 8. Message: {message}")
                    sign_key = init_data.get("sign_key")
                    sign_check = init_data.get("sign_check")
                    if not sign_key or not sign_check:
                        raise Exception(f"Incomplete secondary authentication info for {file_name}.")
                    calculated_sign_val = self.calculate_range_sha1(local_file_path, sign_check)
                    if not calculated_sign_val:
                        raise Exception(f"Failed to calculate secondary authentication SHA1 for {file_name}.")
                    logging.info("Performing secondary authentication...")
                    auth_init_response = self.upload_init(
                        file_name=file_name, file_size=file_size, target=target, fileid=file_sha1,
                        preid=pre_sha1, topupload=topupload, sign_key=sign_key, sign_val=calculated_sign_val
                    )
                    if not auth_init_response:
                        raise Exception("Upload initialization after secondary auth failed.")
                    init_data = auth_init_response.get("data")
                    if not init_data:
                        raise Exception("Upload initialization response data is empty after secondary auth.")
                    status = init_data.get("status")
                    message = auth_init_response.get("message", "Unknown message")
                    if status == 2:
                        logging.info(f"File '{file_name}' (after secondary auth) quick transfer successful! File ID: {init_data.get('file_id')}.")
                        return True, f"Quick transfer successful (after secondary auth): {file_name}"
                    elif status != 1:
                        raise Exception(f"Unexpected status after secondary auth: {status}. Message: {message}")
                if status == 1:
                    oss_credentials = self.get_upload_token()
                    if not oss_credentials:
                        raise Exception(f"Failed to get upload credentials for {file_name}.")
                    callback_nested_data = init_data.get("callback", {})
                    callback_info_json_string_val = callback_nested_data.get("callback")
                    callback_var_json_string_val = callback_nested_data.get("callback_var")
                    bucket = init_data.get("bucket")
                    object_id_from_init = init_data.get("object")
                    if not all([bucket, object_id_from_init, callback_info_json_string_val, callback_var_json_string_val, oss_credentials]):
                        raise Exception(f"Incomplete data for standard upload: {file_name}")
                    actual_object_key = object_id_from_init
                    if actual_object_key.startswith(f"{bucket}/"):
                        actual_object_key = actual_object_key[len(f"{bucket}/"):]
                    logging.info(f"Executing standard upload of file '{file_name}' to object storage.")
                    upload_success = self.upload_to_object_storage(
                        file_path=local_file_path, bucket_name=bucket, object_id=actual_object_key,
                        file_size=file_size, file_sha1=file_sha1, oss_credentials_for_upload=oss_credentials,
                        callback_info_json_string=callback_info_json_string_val,
                        callback_var_json_string=callback_var_json_string_val,
                    )
                    if upload_success:
                        logging.info(f"File '{file_name}' successfully uploaded to object storage.")
                        return True, f"Upload successful: {file_name}"
                    else:
                        raise Exception(f"upload_to_object_storage returned False for {file_name}")
                else:
                    raise Exception(f"Upload initialization returned unexpected status: {status}. Message: {message}")
            except Exception as e:
                logging.error(f"Error during upload of '{file_name}' (Attempt {attempt + 1}/{self.config.UPLOAD_RETRY_COUNT}): {e}")
                if attempt < self.config.UPLOAD_RETRY_COUNT - 1:
                    logging.info(f"Retrying task for '{file_name}' in {self.config.UPLOAD_RETRY_DELAY_SECONDS} seconds...")
                    time.sleep(self.config.UPLOAD_RETRY_DELAY_SECONDS)
                else:
                    logging.error(f"Upload of '{file_name}' failed after all retries.")
                    return False, f"Upload failed after all retries: {file_name} - Last error: {e}"
        return False, f"Upload failed for '{file_name}' after all retries."
    def upload_paths_to_target(self, local_paths: List[str], target_cid: str) -> List[Tuple[bool, str]]:
        processing_queue = deque()
        remote_dir_cache = {}
        files_for_concurrent_upload = []
        upload_results = []
        for path_input in local_paths:
            abs_path_input = os.path.abspath(path_input)
            if not os.path.exists(abs_path_input):
                logging.warning(f"Path '{abs_path_input}' does not exist. Skipped.")
                upload_results.append((False, f"Path does not exist: {path_input}"))
                continue
            if os.path.isfile(abs_path_input):
                processing_queue.append({'type': 'file', 'path': abs_path_input, 'remote_parent_cid': target_cid})
            elif os.path.isdir(abs_path_input):
                processing_queue.append({'type': 'folder_creation', 'path': abs_path_input, 'remote_parent_cid': target_cid})
        logging.info(f"Preparing to upload {len(local_paths)} local items (or their contents) to 115 cloud drive.")
        while processing_queue:
            item_data = processing_queue.popleft()
            item_type = item_data['type']
            local_path = item_data['path']
            remote_parent_cid_for_item = item_data['remote_parent_cid']
            if item_type == 'file':
                files_for_concurrent_upload.append((local_path, remote_parent_cid_for_item))
            elif item_type == 'folder_creation':
                folder_name = os.path.basename(local_path)
                if remote_parent_cid_for_item not in remote_dir_cache:
                    logging.debug(f"Cache miss for CID '{remote_parent_cid_for_item}'. Fetching its contents now.")
                    remote_subfolders = {}
                    offset = 0
                    total_items_in_parent = -1
                    while True:
                        parent_items, current_total = self.api_service.fetch_files_in_directory_page(
                            cid=remote_parent_cid_for_item,
                            limit=self.config.API_FETCH_LIMIT,
                            offset=offset,
                            show_dir="1"
                        )
                        if total_items_in_parent == -1:
                            total_items_in_parent = current_total
                        if not parent_items:
                            break
                        for item in parent_items:
                            if self.is_item_folder(item):
                                name = self._get_item_attribute(item, "fn", "file_name")
                                fid = self._get_item_attribute(item, "fid", "file_id")
                                if name and fid:
                                    remote_subfolders[name] = fid
                        offset += len(parent_items)
                        if total_items_in_parent == 0 or offset >= total_items_in_parent:
                            break
                    remote_dir_cache[remote_parent_cid_for_item] = remote_subfolders
                    logging.debug(f"Cached {len(remote_subfolders)} subfolders for CID '{remote_parent_cid_for_item}'.")
                existing_folder_id = remote_dir_cache[remote_parent_cid_for_item].get(folder_name)
                new_folder_id = None
                if existing_folder_id:
                    logging.info(f"Remote folder '{folder_name}' already exists in cache (ID: {existing_folder_id}). Will use it.")
                    new_folder_id = existing_folder_id
                else:
                    logging.info(f"Remote folder '{folder_name}' not found in cache. Creating it now.")
                    created_folder_id, _, error_msg = self.api_service.create_folder(remote_parent_cid_for_item, folder_name)
                    if created_folder_id:
                        new_folder_id = created_folder_id
                        remote_dir_cache[remote_parent_cid_for_item][folder_name] = new_folder_id
                        upload_results.append((True, f"Folder '{folder_name}' created."))
                    else:
                        logging.error(f"Failed to create remote folder '{folder_name}': {error_msg}. Skipping its contents.")
                        upload_results.append((False, f"Folder creation failed: {folder_name} - {error_msg}"))
                        continue
                if new_folder_id:
                    try:
                        for entry in os.listdir(local_path):
                            full_entry_path = os.path.join(local_path, entry)
                            if os.path.isfile(full_entry_path):
                                processing_queue.append({'type': 'file', 'path': full_entry_path, 'remote_parent_cid': new_folder_id})
                            elif os.path.isdir(full_entry_path):
                                processing_queue.append({'type': 'folder_creation', 'path': full_entry_path, 'remote_parent_cid': new_folder_id})
                    except OSError as e:
                        logging.error(f"Error listing contents of local folder '{local_path}': {e}")
                        upload_results.append((False, f"Error listing contents of folder '{local_path}': {e}"))
        logging.info(f"Identified {len(files_for_concurrent_upload)} files for concurrent upload.")
        # 替换原来的线程池上传逻辑
        if files_for_concurrent_upload:
            logging.info(f"Uploading {len(files_for_concurrent_upload)} files using {self.config.UPLOAD_CONCURRENT_THREADS} concurrent threads.")
            with ThreadPoolExecutor(max_workers=self.config.UPLOAD_CONCURRENT_THREADS) as executor:
                futures = {
                    executor.submit(self._execute_single_file_upload_task, file_path, target_cid): file_path
                    for file_path, target_cid in files_for_concurrent_upload if file_path is not None
                }
                for future in as_completed(futures):
                    original_file_path = futures[future]
                    try:
                        success, msg = future.result()
                        upload_results.append((success, msg))
                    except Exception as exc:
                        logging.error(f"Unexpected exception during upload of '{original_file_path}': {exc}")
                        upload_results.append((False, f"Upload exception '{original_file_path}': {exc}"))
        else:
            logging.info("No files to upload after folder processing.")
        return upload_results
class BrowserState:
    def __init__(self, initial_cid: str, initial_browse_params: Dict, initial_api_chunk: List[Dict], total_items: int, config: AppConfig):
        self.config = config
        self.title = "Root Quick Browse List"
        self.parent_cid_stack: List[Dict] = []
        self.current_browse_params = initial_browse_params.copy()
        self.current_browse_params['cid'] = initial_cid
        self.current_fetch_function = None
        self._last_fetched_params_hash: Union[str, None] = None
        self._api_cache_buffer: List[Dict] = initial_api_chunk if initial_api_chunk is not None else []
        self._api_cache_start_offset = 0
        self.current_offset = 0
        self.total_items = total_items
        self.explorable_count = min(total_items, self.config.MAX_SEARCH_EXPLORE_COUNT)
        self.showing_all_items = False
        self._all_items_cache: List[Dict] = []
        self.current_display_page = 1
        self.total_display_pages = 1
        self._force_full_display_next_render = False
        self.marked_for_move_file_ids: List[str] = []
        self.current_folder_id = initial_cid
        self.target_download_dir = self.config.DEFAULT_TARGET_DOWNLOAD_DIR
        if initial_api_chunk is not None and len(initial_api_chunk) > 0:
            sorted_params = sorted(self.current_browse_params.items())
            self._last_fetched_params_hash = str(hash(frozenset(sorted_params)))
    def create_snapshot(self) -> Dict:
        return {
            'fetch_func': self.current_fetch_function,
            'title': self.title,
            'browse_params': self.current_browse_params.copy(),
            'last_hash': self._last_fetched_params_hash,
            'cache_buffer': self._api_cache_buffer.copy(),
            'cache_start_offset': self._api_cache_start_offset,
            'total_items': self.total_items,
            'explorable_count': self.explorable_count,
            'current_offset': self.current_offset,
            'showing_all_items': self.showing_all_items,
            'all_items_cache': self._all_items_cache.copy()
        }
    def restore_from_snapshot(self, snapshot: Dict):
        self.current_fetch_function = snapshot['fetch_func']
        self.title = snapshot['title']
        self.current_browse_params = snapshot['browse_params'].copy()
        self._last_fetched_params_hash = snapshot['last_hash']
        self._api_cache_buffer = snapshot['cache_buffer'].copy()
        self._api_cache_start_offset = snapshot['cache_start_offset']
        self.current_offset = snapshot['current_offset']
        self.total_items = snapshot['total_items']
        self.explorable_count = snapshot['explorable_count']
        self.showing_all_items = snapshot['showing_all_items']
        self._all_items_cache = snapshot['all_items_cache'].copy()
        self.current_folder_id = _get_item_attribute(self.current_browse_params, 'cid', default_value=self.config.ROOT_CID)
    def get_current_display_items(self) -> List[Dict]:
        if self.showing_all_items:
            return self._all_items_cache
        else:
            start_index_in_cache = self.current_offset - self._api_cache_start_offset
            end_index_in_cache = start_index_in_cache + self.config.PAGINATOR_DISPLAY_SIZE
            return self._api_cache_buffer[start_index_in_cache:end_index_in_cache]
class UIRenderer:
    def __init__(self, config: AppConfig, state: BrowserState):
        self.config = config
        self.state = state
    def display_paginated_items_list(self, page_items_to_display: List[Dict], force_full_display: bool = False):
        logging.info(f"--- {self.state.title} Page {self.state.current_display_page}/{self.state.total_display_pages}  ---")
        if not page_items_to_display:
            logging.info("No items to display on the current page.")
            return
        processed_rows_data = []
        display_full_details = not self.config.show_list_short_form or force_full_display
        for item_raw in page_items_to_display:
            parsed_parts = format_file_item(item_raw)
            processed_rows_data.append(parsed_parts)
        max_idx_len = max(len(str(i)) for i in range(len(page_items_to_display)))
        max_name_value_len = max(len(row["name_value"]) for row in processed_rows_data)
        max_size_display_len = 0
        max_id_display_len = max(len(row.get("id_value", "")) for row in processed_rows_data)
        max_pick_code_display_len = max(len(row.get("pick_code_value", "")) for row in processed_rows_data)
        max_folder_size_display_len = 0
        max_file_count_display_len = 0
        max_folder_count_display_len = 0
        max_path_display_len = 0
        if display_full_details:
            for i, row_data in enumerate(processed_rows_data):
                item = page_items_to_display[i]
                if not is_item_folder(item):
                    size_str = row_data.get("size_value", "")
                    max_size_display_len = max(max_size_display_len, len(size_str))
                else:
                    if item.get('_details'):
                        max_folder_size_display_len = max(max_folder_size_display_len, len(row_data.get("folder_size_display", "")))
                        max_file_count_display_len = max(max_file_count_display_len, len(row_data.get("file_count_display", "")))
                        max_folder_count_display_len = max(max_folder_count_display_len, len(row_data.get("folder_count_display", "")))
                if item.get('_details'):
                    max_path_display_len = max(max_path_display_len, len(row_data.get("path_display", "")))
        for i, (row_data, item) in enumerate(zip(processed_rows_data, page_items_to_display)):
            idx_padded = str(i).rjust(max_idx_len)
            name_value = row_data['name_value']
            if is_item_folder(item):
                colored_name = f"{COLOR_FOLDER}{name_value}{COLOR_RESET}"
            else:
                raw_size = _get_item_attribute(item, "fs", "file_size")
                try:
                    if raw_size is None:
                        size_bytes = None
                    elif isinstance(raw_size, str):
                        size_bytes = int(raw_size) if raw_size.isdigit() else None
                    elif isinstance(raw_size, (int, float)):
                        size_bytes = int(raw_size)
                    else:
                        size_bytes = None
                    if size_bytes is not None:
                        if size_bytes <= 10 * 1024 * 1024:
                            colored_name = f"{COLOR_SIZE_SMALL}{name_value}{COLOR_RESET}"
                        elif size_bytes <= 1024 * 1024 * 1024:
                            colored_name = f"{COLOR_SIZE_MEDIUM}{name_value}{COLOR_RESET}"
                        elif size_bytes <= 6 * 1024 * 1024 * 1024:
                            colored_name = f"{COLOR_SIZE_LARGE}{name_value}{COLOR_RESET}"
                        elif size_bytes <= 20 * 1024 * 1024 * 1024:
                            colored_name = f"{COLOR_SIZE_LARGE3}{name_value}{COLOR_RESET}"
                        else:
                            colored_name = f"{COLOR_SIZE_LARGE2}{name_value}{COLOR_RESET}"
                    else:
                        colored_name = name_value
                except (ValueError, TypeError):
                    colored_name = name_value
            main_line = f"[{idx_padded}] {colored_name}"
            logging.info(main_line)
            if display_full_details:
                detail_lines = []
                if not is_item_folder(item):
                    size_str = row_data.get("size_value", "")
                    detail_lines.append(f"Size: {size_str.ljust(max_size_display_len)}")
                if is_item_folder(item) and item.get('_details'):
                    if row_data.get("folder_size_display"):
                        detail_lines.append(f"Folder Size: {row_data['folder_size_display'].ljust(max_folder_size_display_len)}")
                    if row_data.get("file_count_display"):
                        detail_lines.append(f"File Count: {row_data['file_count_display'].ljust(max_file_count_display_len)}")
                    if row_data.get("folder_count_display"):
                        detail_lines.append(f"Folder Count: {row_data['folder_count_display'].ljust(max_folder_count_display_len)}")
                if item.get('_details') and row_data.get("path_display"):
                    detail_lines.append(f"Path: {row_data['path_display'].ljust(max_path_display_len)}")
                for line in detail_lines:
                    logging.info(f"{line}")
        logging.info("--- List End ---")
        
    def display_help(self):
        logging.info("\n--- 115 网盘管理脚本使用说明 ---")

        logging.info("\n【一】交互模式命令（在脚本运行后输入）")
        commands_info = {
            'cd <索引> / ..': '进入指定索引的文件夹，或返回上一级目录。',
            'ls': '重新列出当前页内容。',
            'g <页码>': '跳转到指定页码。',
            'n': '下一页。',
            'p': '上一页。',
            's': '设置当前列表的排序与筛选条件（如按大小、类型排序）。',
            'f <关键词>': '按关键词搜索文件/文件夹（可附加类型、后缀等高级筛选）。',
            'a': '获取并显示当前上下文中的所有项目（适用于大目录，可能较慢）。',
            't': '切换显示模式：简洁（仅文件名）/ 详细（含大小、路径等）。',
            'd <索引> / a': '下载选中文件，或递归下载整个文件夹。支持范围：d 0,2-5 或 d a。',
            'v <索引>': '智能播放/预览文件（根据文件类型调用 mpv 或 Infuse）。',
            'i <索引> / a': '获取选中项目详细信息（如文件夹内文件数、总大小、完整路径）。',
            'c <索引> / a': '递归收集指定文件夹所有内容的原始 JSON 数据并保存到本地。',
            'mc': '切换 "c" 命令是否并发获取详情（启用后速度更快）。',
            'save <文件名.json> / a <文件名.json>': '将当前页或所有已加载项目保存为 JSON 文件。',
            'm <索引> / a': '标记要移动的文件/文件夹（用于后续 mm 或 merge）。',
            'mm': '将所有已标记项目移动到当前目录。',
            'merge': '智能合并：将标记的文件夹内容“注入”到当前目录同名文件夹中（避免重名冲突）。',
            'add <文件夹名>': '在当前目录创建新文件夹。',
            'rename <索引> <新名称>': '重命名指定索引的文件或文件夹。',
            'del <索引> / a': '删除选中的文件/文件夹（需二次确认）。',
            'cloud': '添加离线下载任务（支持多链接）。',
            'upload': '上传本地文件或文件夹到网盘（支持预设目标目录）。',
            'up <索引>': '查看选中项目完整路径层级，并可跳转到任意上级目录。',
            'rs <索引> [阈值]': '递归扫描文件夹，列出大小 ≤ 阈值的子文件夹（如 rs 0 1GB），并支持交互式删除。',
            'page1': '对当前目录下的所有子文件夹按内容总量智能分组（≤10万项/组），创建 [1/2] 分页文件夹并归档。',
            'page2': '对当前目录所有项目按数量分块（每块200项），创建 [2/2] 分页文件夹并归档。',
            'h': '显示本帮助信息。',
            'q': '退出程序。'
        }
        max_cmd_len = max(len(cmd) for cmd in commands_info)
        sorted_commands = sorted(commands_info.items())
        for cmd, desc in sorted_commands:
            logging.info(f"{cmd.ljust(max_cmd_len)} : {desc}")

        logging.info("\n【二】命令行参数运行模式（非交互式批量执行）")
        logging.info("  启动脚本时可直接传入命令序列，用'=' 分隔，自动依次执行。")
        logging.info("  示例：")
        logging.info("    python my115.py = s 2 0 4 =  1 = d a = q")
        logging.info("  支持的参数命令包括：")
        logging.info("    - 数字索引（如 0）：进入该索引的文件夹，或加载文件详情")
        logging.info("    - n / p / g <页码>：翻页")
        logging.info("    - s <o> <asc> <type> [suffix]：设置排序（如 s 2 0 4 表示按大小降序+视频）")
        logging.info("    - f <关键词>：搜索")
        logging.info("    - cd <CID>：切换到指定 CID 目录")
        logging.info("    - v/d/i/a <索引或 a>：播放/下载/查看详情/获取全部")
        logging.info("    - upload <本地路径> [目标CID或预设名]")
        logging.info("    - cloud <URL列表> [目标CID或预设名]")
        logging.info("    - q：执行完前面命令后直接退出（不进入交互）")
        logging.info("\n  注意：命令链中若未包含 'q'，所有参数执行完毕后会自动进入交互模式。")

        logging.info("\n--------------------------")
class CommandProcessor:
    def __init__(self, browser_instance):
        self.browser = browser_instance
        self.command_map = {
            'p': self.browser._command_p,
            'n': self.browser._command_n,
            'a': self.browser._command_a,
            'merge': self.browser._command_merge,  
            'b': self.browser._command_b,
            'q': lambda *args: CMD_EXIT,
            's': self.browser._command_s,
            't': self.browser._command_t,
            'mc': self.browser._command_mc,
            'mm': self.browser._command_mm,
            'ls': lambda *args: CMD_RENDER_NEEDED,
            'h': self.browser._command_h,
            'cloud': self.browser._command_cloud,
            'upload': self.browser._command_upload,
        }
        self.prefix_command_map = {
            'g': self.browser._command_g,
            'f': self.browser._command_f,
            'd': self.browser._command_d,
            'v': self.browser._command_v,
            'page1': self.browser._command_page1,
            'page2': self.browser._command_page2,  
            'rs': self.browser._command_rs,   
            'i': self.browser._command_i,
            'c': self.browser._command_c,
            'up': self.browser._command_up,
            'm': self.browser._command_m,
            'save': self.browser._command_save,
            'cd': self.browser._command_cd,
            'add': self.browser._command_add,
            'rename': self.browser._command_rename,
            'del': self.browser._command_del,
        }
    def process_command(self, user_input: str, page_items: List[Dict]) -> str:
        command_parts = user_input.split(' ', 1)
        command_key = command_parts[0]
        if command_key in self.command_map:
            if command_key == 'h':
                self.command_map[command_key]()
                return CMD_CONTINUE_INPUT
            return self.command_map[command_key]()
        if command_key in self.prefix_command_map:
            return self.prefix_command_map[command_key](user_input, page_items)
        return self.browser._command_index_selection(user_input, page_items)
class FileBrowser:
    def __init__(self, initial_cid: str, initial_browse_params: Dict, initial_api_chunk: List[Dict], total_items: int, config: AppConfig):
        self.config = config
        self.api_service = ApiService(self.config)
        self.state = BrowserState(initial_cid, initial_browse_params, initial_api_chunk, total_items, self.config)
        self.ui_renderer = UIRenderer(self.config, self.state)
        self.command_processor = CommandProcessor(self)
        self.state.current_fetch_function = self.api_service.fetch_files_in_directory_page
    def _refresh_paginator_data(self) -> None:
        current_fetch_func = self.state.current_fetch_function
        current_browse_params = self.state.current_browse_params.copy()
        sorted_params = sorted(current_browse_params.items())
        params_hash = str(hash(frozenset(sorted_params)))
        required_api_fetch_offset = (self.state.current_offset // self.config.API_FETCH_LIMIT) * self.config.API_FETCH_LIMIT
        cache_end_offset = self.state._api_cache_start_offset + len(self.state._api_cache_buffer)
        if (params_hash == self.state._last_fetched_params_hash and
            self.state._api_cache_start_offset <= required_api_fetch_offset < cache_end_offset and
            len(self.state._api_cache_buffer) > 0):
            logging.debug(f"Cache hit for offset {required_api_fetch_offset}. Reusing cached data.")
            return
        logging.debug(f"Cache miss or parameters changed. Fetching new data chunk from API (offset: {required_api_fetch_offset}, limit: {self.config.API_FETCH_LIMIT}).")
        api_call_kwargs = current_browse_params.copy()
        api_call_kwargs.update({"limit": self.config.API_FETCH_LIMIT, "offset": required_api_fetch_offset})
        fetched_api_chunk, new_total_count = [], 0
        main_param_name_for_api_call = 'cid' if current_fetch_func == self.api_service.fetch_files_in_directory_page else 'search_value'
        main_param_value_for_call = api_call_kwargs.pop(main_param_name_for_api_call, self.config.ROOT_CID if main_param_name_for_api_call == 'cid' else '')
        fetched_api_chunk, new_total_count = current_fetch_func(**{main_param_name_for_api_call: main_param_value_for_call}, **api_call_kwargs)
        self.state.total_items = new_total_count
        self.state.explorable_count = min(new_total_count, self.config.MAX_SEARCH_EXPLORE_COUNT if current_fetch_func == self.api_service.search_files else new_total_count)
        self.state._api_cache_buffer = fetched_api_chunk
        self.state._api_cache_start_offset = required_api_fetch_offset
        self.state._last_fetched_params_hash = params_hash
        if not fetched_api_chunk and self.state.explorable_count > 0:
            logging.warning(f"Warning: API returned no data or an error occurred. Attempting to adjust offset.")
            self.state.current_offset = max(0, self.state.current_offset - self.config.PAGINATOR_DISPLAY_SIZE)
    def _encode_url_for_infuse_param(self, content_url: str) -> str:
        encoded_content_url = urllib.parse.quote(content_url, safe='')
        return f"url={encoded_content_url}"
    def _play_with_mpv(self, url: str, file_name: str):
        mpv_command_base = []
        is_termux_am_start_mode = (self.config.DEFAULT_PLAYBACK_STRATEGY == 1 and "TERMUX_VERSION" in os.environ)
        if is_termux_am_start_mode:
            response = input("立即播放？(y/n): ").lower().strip()
            if response == 'y':
                mpv_command_base = ['am', 'start', '-n', 'xyz.re.player.ex/xyz.re.player.ex.MainActivity', url]
        else:
            mpv_command_base = ['mpv', url, f'--user-agent={self.config.USER_AGENT}']
        subprocess.run(mpv_command_base)
    def _play_with_infuse(self, url: str, file_name: str):
        encoded_url_param = self._encode_url_for_infuse_param(url)
        infuse_scheme_url = f"infuse://x-callback-url/play?{encoded_url_param}"
        logging.info(f"Playing '{file_name}' with Infuse.")
        logging.debug(f"Infuse URL: {infuse_scheme_url}")
        confirm_choice = input(f"Confirm playing '{file_name}' with Infuse (current Infuse playback might be replaced)? (y/n): ").strip().lower()
        if confirm_choice == "y":
            try:
                subprocess.run(['open', infuse_scheme_url], check=True)
            except FileNotFoundError:
                logging.error("Error: 'open' command not found. This command is typically available on macOS.")
                logging.error(f"You can manually open Infuse with this URL: {infuse_scheme_url}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Infuse playback failed, return code: {e.returncode}")
            except Exception as e:
                logging.error(f"Error starting Infuse: {e}")
        else:
            logging.info("Infuse playback cancelled.")
    def _download_single_item_and_link(self, item: Dict, full_target_path: str) -> Tuple[bool, str, Union[str, None]]:
        file_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown File")
        file_id = _get_item_attribute(item, "fid", "file_id", default_value="unknown_id")
        download_url, _, error_message = self.api_service.get_download_link_details(item)
        if download_url:
            save_dir = os.path.dirname(full_target_path)
            original_file_name = os.path.basename(full_target_path)
            # 构造唯一文件名：file_id__original_name
            unique_file_name = f"{file_id}__{original_file_name}"
            success, downloaded_size, download_error_msg = self.api_service.download_file(download_url, unique_file_name, save_dir)
            return success, file_name, download_error_msg
        else:
            return False, file_name, error_message or "Failed to get download link"
    def _execute_download_queue(self, items_with_paths_to_download: List[Tuple[Dict, str]], prefix_item_name: str = "Download"):
        if not items_with_paths_to_download:
            logging.info(f"{prefix_item_name}: No files to download.")
            return
        logging.debug(f"Preparing to download {len(items_with_paths_to_download)} files.")
        with ThreadPoolExecutor(max_workers=self.config.DOWNLOAD_CONCURRENT_THREADS) as executor:
            futures = [
                executor.submit(self._download_single_item_and_link, item, full_target_path)
                for item, full_target_path in items_with_paths_to_download
            ]
            for i, future in enumerate(as_completed(futures)):
                try:
                    success, file_name, error_msg = future.result()
                    if success:
                        logging.info(f" {i+1}/{len(items_with_paths_to_download)} over:'{file_name}'")
                    else:
                        logging.error(f"File download failed: {file_name} - {error_msg}")
                except Exception as exc:
                    logging.error(f"An unexpected exception occurred during file download: {exc}")
    def _generic_traverse_folder_items_concurrent(
        self,
        root_cid: str,
        item_handler_func: callable,
        folder_handler_func: callable = None,
        base_kwargs: dict = None,
        processed_cids: set = None
    ):
        """
        并发广度优先遍历目录树。
        :param root_cid: 起始目录 CID
        :param item_handler_func: 处理文件的回调函数 (item, recursion_level=0, **kwargs)
        :param folder_handler_func: 处理文件夹的回调函数 (folder, recursion_level=0, **kwargs)
        :param base_kwargs: 传递给 handler 的额外参数（如 current_relative_path, base_download_path 等）
        :param processed_cids: 已处理的 CID 集合（用于去重）
        """
        if processed_cids is None:
            processed_cids = set()
        if base_kwargs is None:
            base_kwargs = {}
        from collections import deque
        # 初始化队列：(cid, relative_path, recursion_level)
        queue = deque()
        initial_rel_path = base_kwargs.get('current_relative_path', '')
        queue.append((root_cid, initial_rel_path, 0))
        processed_cids.add(root_cid)
        def _fetch_items_in_cid(cid: str, rel_path: str):
            """拉取单个目录下的所有 items"""
            items_collected = []
            offset = 0
            page_size = self.config.API_FETCH_LIMIT
            dir_fetch_kwargs = self.config.COMMON_BROWSE_FETCH_PARAMS.copy()
            total = -1
            while total == -1 or offset < total:
                page_items, current_total = self.api_service.fetch_files_in_directory_page(
                    cid=cid, limit=page_size, offset=offset, **dir_fetch_kwargs
                )
                if total == -1:
                    total = current_total
                if not page_items:
                    break
                for item in page_items:
                    item_copy = item.copy()
                    name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown")
                    full_rel = join_relative_path(rel_path, name)
                    item_copy["_relative_path"] = full_rel
                    items_collected.append(item_copy)
                offset += len(page_items)
            return items_collected
        # ============ 改为使用统一并发函数 ============
        while queue:
            batch = []
            while queue and len(batch) < self.config.API_CONCURRENT_THREADS:
                cid, rel_path, level = queue.popleft()
                batch.append((cid, rel_path, level))
            if not batch:
                break
            # 构造参数列表
            fetch_args_list = [{"cid": cid, "rel_path": rel_path} for cid, rel_path, _ in batch]
            # 包装函数以适配统一并发
            def wrapped_fetch(args):
                return _fetch_items_in_cid(args['cid'], args['rel_path'])
            results = self.api_service._fetch_concurrent_pages(wrapped_fetch, fetch_args_list)
            # 处理结果
            for (cid, rel_path, level), items in zip(batch, results):
                if items is None:
                    logging.error(f"Failed to fetch items in CID {cid}")
                    continue
                for item in items:
                    if is_item_folder(item):
                        if folder_handler_func:
                            folder_handler_func(item, level, **base_kwargs)
                        sub_cid = _get_item_attribute(item, "fid", "file_id")
                        if sub_cid and sub_cid not in processed_cids:
                            processed_cids.add(sub_cid)
                            folder_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown Folder")
                            new_rel_path = join_relative_path(rel_path, folder_name)
                            queue.append((sub_cid, new_rel_path, level + 1))
                    else:
                        if item_handler_func:
                            item_handler_func(item, level, **base_kwargs)
    def _generic_traverse_folder_items(self, current_cid: str, item_handler_func: callable, folder_handler_func: callable = None, recursion_level: int = 0, processed_cids: set = None, **kwargs):
        if processed_cids is None:
            processed_cids = set()
        if current_cid in processed_cids:
            logging.debug(f"{'  ' * recursion_level}Skipping already processed CID: {current_cid}")
            return
        processed_cids.add(current_cid)
        log_prefix = "  " * recursion_level
        logging.debug(f"{log_prefix}Entering generic_traverse, CID: {current_cid}")
        page_size = self.config.API_FETCH_LIMIT
        offset = 0
        total_items_in_current_folder = -1
        dir_fetch_kwargs = self.config.COMMON_BROWSE_FETCH_PARAMS.copy()
        while total_items_in_current_folder == -1 or offset < total_items_in_current_folder:
            page_items, current_total_count = self.api_service.fetch_files_in_directory_page(
                cid=current_cid, limit=page_size, offset=offset, **dir_fetch_kwargs
            )
            if total_items_in_current_folder == -1:
                total_items_in_current_folder = current_total_count
            if not page_items:
                break
            logging.debug(f"{log_prefix}Fetched {len(page_items)} items for CID {current_cid} at offset {offset}.")
            for item in page_items:
                if is_item_folder(item):
                    if folder_handler_func:
                        folder_handler_func(item, recursion_level, **kwargs)
                    sub_cid = _get_item_attribute(item, "fid", "file_id")
                    if sub_cid and sub_cid != self.config.ROOT_CID:
                        current_relative_path = kwargs.get('current_relative_path', '')
                        folder_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown Folder")
                        new_relative_path = join_relative_path(current_relative_path, folder_name)
                        new_kwargs = kwargs.copy()
                        new_kwargs['current_relative_path'] = new_relative_path
                        self._generic_traverse_folder_items(sub_cid, item_handler_func, folder_handler_func, recursion_level + 1, processed_cids, **new_kwargs)
                    elif not sub_cid:
                        logging.warning(f"{log_prefix}Skipping recursive collection for item with invalid CID: {item}")
                else:
                    item_handler_func(item, recursion_level, **kwargs)
            offset += page_size
        logging.debug(f"{log_prefix}Exiting generic_traverse, CID: {current_cid}.")
    def _list_folders_in_cid(self, cid: str) -> Dict[str, str]:
        """返回 {folder_name_lower: folder_id}，用于大小写不敏感匹配"""
        folders = {}
        offset = 0
        while True:
            items, _ = self.api_service.fetch_files_in_directory_page(
                cid=cid, limit=self.config.API_FETCH_LIMIT, offset=offset, show_dir="1"
            )
            if not items:
                break
            for item in items:
                if is_item_folder(item):
                    name = _get_item_attribute(item, "fn", "file_name")
                    fid = _get_item_attribute(item, "fid", "file_id")
                    if name and fid:
                        folders[name.lower()] = fid  # ← 小写 key
            offset += len(items)
        return folders
    def _smart_move_recursive(
        self,
        source_items: List[Dict],
        target_cid: str,
        target_dir_cache: Dict[Tuple[str, str], str] = None
    ) -> Tuple[bool, int, int]:
        if target_dir_cache is None:
            target_dir_cache = {}
        MAX_ITEMS = self.config.MOVE_MAX_FILE_IDS
        RATE_LIMIT = self.config.MOVE_RATE_LIMIT_FILES_PER_SECOND
        cache_key = ('folders', target_cid)
        if cache_key in target_dir_cache:
            target_folders = target_dir_cache[cache_key]
        else:
            target_folders = self._list_folders_in_cid(target_cid)
            target_dir_cache[cache_key] = target_folders
        groups: Dict[str, List[Tuple[str, int, bool]]] = {}
        for item in source_items:
            fid = _get_item_attribute(item, "fid", "file_id")
            name = _get_item_attribute(item, "fn", "file_name")
            is_folder = is_item_folder(item)
            if not fid or not name:
                continue
            name_lower = name.lower()
            if not is_folder:
                groups.setdefault(target_cid, []).append((fid, 1, False))
            else:
                details = self.api_service.get_item_details(fid)
                if not details:
                    continue
                total_est = self._get_estimated_total_items(details)
                if name_lower in target_folders:
                    existing_cid = target_folders[name_lower]
                    # === 修复点：逻辑反转 ===
                    if total_est <= MAX_ITEMS:
                        # ✅ 小文件夹：直接移动整个文件夹（不展开！）
                        groups.setdefault(target_cid, []).append((fid, total_est, True))
                    else:
                        # ❌ 大文件夹：必须展开内容，递归移动到 existing_cid
                        logging.info(f"Folder '{name}' exceeds limit ({total_est} > {MAX_ITEMS}), expanding contents into existing folder.")
                        sub_items = []
                        offset = 0
                        while True:
                            page, _ = self.api_service.fetch_files_in_directory_page(
                                cid=fid, limit=self.config.API_FETCH_LIMIT, offset=offset, show_dir="1"
                            )
                            if not page:
                                break
                            sub_items.extend(page)
                            offset += len(page)
                        if sub_items:
                            no_fatal, _, _ = self._smart_move_recursive(sub_items, existing_cid, target_dir_cache)
                            if not no_fatal:
                                pass
                        # 注意：原文件夹内容已移走，原 folder_id 不再移动（避免空文件夹残留）
                        # 所以这里 **不要** 再 append 到 groups
                else:
                    # 目标不存在同名文件夹
                    if total_est <= MAX_ITEMS:
                        # ✅ 小文件夹：直接移动到 target_cid
                        groups.setdefault(target_cid, []).append((fid, total_est, True))
                    else:
                        # ❌ 大文件夹：需创建新文件夹，再展开内容移入
                        logging.info(f"Folder '{name}' exceeds limit ({total_est} > {MAX_ITEMS}), creating new folder and expanding contents.")
                        new_target_cid, _, err = self.api_service.create_folder(target_cid, name)
                        if not new_target_cid:
                            continue
                        target_folders[name_lower] = new_target_cid
                        target_dir_cache[cache_key] = target_folders
                        sub_items = []
                        offset = 0
                        while True:
                            page, _ = self.api_service.fetch_files_in_directory_page(
                                cid=fid, limit=self.config.API_FETCH_LIMIT, offset=offset, show_dir="1"
                            )
                            if not page:
                                break
                            sub_items.extend(page)
                            offset += len(page)
                        if sub_items:
                            no_fatal, _, _ = self._smart_move_recursive(sub_items, new_target_cid, target_dir_cache)
                            if not no_fatal:
                                pass
                        # 同样，内容已移走，原 folder_id 不再移动
                        # 所以这里 **不要** 再 append 到 groups
        success_count = 0
        fail_count = 0
        for tgt_cid, items in groups.items():
            fids = [fid for fid, _, _ in items]
            total_est = sum(est for _, est, _ in items)
            if total_est <= MAX_ITEMS:
                if self.api_service.move_files(fids, tgt_cid):
                    success_count += len(fids)
                else:
                    fail_count += len(fids)
            else:
                # 理论上不会发生（因为已按 <= MAX 分组）
                for fid, est, _ in items:
                    if self.api_service.move_files([fid], tgt_cid):
                        success_count += 1
                    else:
                        fail_count += 1
            if total_est > 0:
                sleep_time = total_est / RATE_LIMIT
                if sleep_time > 0:
                    logging.info(f"Rate limiting: sleeping {sleep_time:.2f} seconds...")
                    time.sleep(sleep_time)
        return True, success_count, fail_count
    
    def _command_rs(self, action_choice: str, page_items: List[Dict]) -> str:
        """
        Recursively Scan folders and list those with size <= threshold.
        Usage: rs <index> [threshold]  or  rs a [threshold]
        Default threshold: 0B (i.e., empty folders)
        Example: rs 0 1GB
        """
        parts = action_choice.split()
        if len(parts) < 2:
            logging.warning("Usage: rs <index> [threshold] or rs a [threshold]. Default threshold is 0B.")
            return CMD_CONTINUE_INPUT
        indices_str = parts[1]
        threshold_str = "0B"
        if len(parts) >= 3:
            threshold_str = parts[2]
        try:
            threshold_bytes = parse_human_readable_size(threshold_str)
        except Exception:
            logging.error(f"Invalid threshold size: '{threshold_str}'. Please use formats like '0B', '1GB', '500MB'.")
            return CMD_CONTINUE_INPUT
        selected_indices = parse_indices_input(indices_str, len(page_items))
        if selected_indices is None or not selected_indices:
            logging.warning("No valid items selected.")
            return CMD_CONTINUE_INPUT
        folders_to_scan = []
        for idx in selected_indices:
            item = page_items[idx]
            if not is_item_folder(item):
                file_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown")
                logging.warning(f"Skipping non-folder item: '{file_name}'.")
                continue
            fid = _get_item_attribute(item, "fid", "file_id")
            name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown")
            if fid:
                folders_to_scan.append((fid, name, name))  # (fid, name, current_path)
        if not folders_to_scan:
            logging.warning("No valid folders to scan.")
            return CMD_CONTINUE_INPUT
        logging.info(f"Recursively scanning {len(folders_to_scan)} folder(s) for size <= {threshold_str} ({threshold_bytes} bytes)...")

        # === 第一阶段：并发广度优先遍历，收集所有 folder_id 和路径 ===
        from collections import deque
        queue = deque(folders_to_scan)
        visited = set()
        all_fids_to_check = set()
        temp_results = []  # (fid, full_path)

        # === 修正：定义辅助函数，接受 **kwargs ===
        def _fetch_subfolders_for_rs(**kwargs):
            parent_fid = kwargs['parent_fid']
            parent_full_path = kwargs['parent_full_path']
            sub_folders = []
            offset = 0
            while True:
                items, _ = self.api_service.fetch_files_in_directory_page(
                    cid=parent_fid, limit=self.config.API_FETCH_LIMIT, offset=offset, show_dir="1"
                )
                if not items:
                    break
                for item in items:
                    if is_item_folder(item):
                        sub_fid = _get_item_attribute(item, "fid", "file_id")
                        sub_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown")
                        if sub_fid:
                            sub_full_path = join_relative_path(parent_full_path, sub_name)
                            sub_folders.append((sub_fid, sub_full_path))
                offset += len(items)
            return sub_folders

        while queue:
            batch = []
            while queue and len(batch) < self.config.API_CONCURRENT_THREADS:
                fid, name, full_path = queue.popleft()
                if fid in visited:
                    continue
                visited.add(fid)
                all_fids_to_check.add(fid)
                temp_results.append((fid, full_path))
                batch.append((fid, full_path))
            
            if not batch:
                break

            # === 构造参数列表：每个元素是 dict，作为 **kwargs 传给 _fetch_subfolders_for_rs ===
            fetch_args_list = [
                {"parent_fid": fid, "parent_full_path": full_path}
                for fid, full_path in batch
            ]
            
            # === 直接传 _fetch_subfolders_for_rs，不再需要 wrapped_fetch ===
            results = self.api_service._fetch_concurrent_pages(_fetch_subfolders_for_rs, fetch_args_list)
            
            # 将结果加入队列
            for sub_folders in results:
                if sub_folders:
                    # 注意：sub_folders 是 [(sub_fid, sub_full_path), ...]
                    # 需要转为 (fid, name, full_path) 格式，name 可用 "" 占位
                    queue.extend([(sub_fid, "", sub_full_path) for sub_fid, sub_full_path in sub_folders])

        # === 第二阶段：批量并发获取详情 ===
        logging.info(f"Fetching details for {len(all_fids_to_check)} folders...")
        fids = list(all_fids_to_check)
        fetch_args_list = [{"file_or_folder_id": fid} for fid in fids]
        results = self.api_service._fetch_concurrent_pages(self.api_service.get_item_details, fetch_args_list)
        details_map = {fid: detail for fid, detail in zip(fids, results) if detail is not None}

        # === 第三阶段：筛选结果 ===
        final_results = []
        for fid, full_path in temp_results:
            details = details_map.get(fid)
            if not details:
                continue
            size_str = details.get("size", "0 B")
            try:
                size_bytes = parse_human_readable_size(size_str)
            except Exception:
                size_bytes = 0
            if size_bytes <= threshold_bytes:
                final_results.append((full_path, size_str, fid))

        if not final_results:
            logging.info(f"No folders found with size <= {threshold_str}.")
            return CMD_CONTINUE_INPUT

        logging.info(f"\n--- Folders with size <= {threshold_str} ({len(final_results)} found) ---")
        for i, (path, size, _) in enumerate(final_results):
            logging.info(f"[{i}] {size:>10}  {path}")
        logging.info("--- End of Results ---")

        # ====== 删除确认子循环 ======
        while True:
            try:
                user_input = input("\nIn 'rs' delete mode. Enter 'del <index>' to delete, or 'q' to quit: ").strip()
            except (EOFError, KeyboardInterrupt):
                logging.info("\nOperation cancelled by user.")
                return CMD_RENDER_NEEDED
            if not user_input:
                continue
            if user_input.lower() == 'q':
                logging.info("Exiting 'rs' delete mode.")
                return CMD_RENDER_NEEDED
            if user_input.lower().startswith('del '):
                try:
                    idx_input = user_input.split(' ', 1)[1].strip()
                    selected_del_indices = parse_indices_input(idx_input, len(final_results))
                    if selected_del_indices is None or not selected_del_indices:
                        logging.warning("Invalid index format.")
                        continue
                    to_delete = []
                    for idx in selected_del_indices:
                        if 0 <= idx < len(final_results):
                            full_path, _, fid = final_results[idx]
                            to_delete.append((idx, full_path, fid))
                        else:
                            logging.warning(f"Index {idx} out of range.")
                    if not to_delete:
                        continue
                    confirm = input(f"⚠️ Confirm deletion of {len(to_delete)} folder(s)? Type 'yes' to proceed: ").strip()
                    if confirm.lower() == 'yes':
                        deleted_indices = []
                        for idx, full_path, fid in to_delete:
                            success, error_msg = self.api_service.delete_files_or_folders([fid])
                            if success:
                                logging.info(f"✅ Successfully deleted folder: {full_path}")
                                deleted_indices.append(idx)
                            else:
                                logging.error(f"❌ Failed to delete folder: {full_path} - {error_msg}")
                            time.sleep(1)
                        for idx in sorted(deleted_indices, reverse=True):
                            final_results.pop(idx)
                        if final_results:
                            logging.info(f"\n--- Remaining folders ({len(final_results)} left) ---")
                            for i, (path, size, _) in enumerate(final_results):
                                logging.info(f"[{i}] {size:>10}  {path}")
                            logging.info("--- End of Results ---")
                        else:
                            logging.info("All matching folders have been deleted.")
                            break
                    else:
                        logging.info("Deletion cancelled.")
                except Exception as e:
                    logging.warning(f"Invalid input: {e}")
            else:
                logging.warning("Only 'del <index>' or 'q' are accepted in this mode.")

    def _get_estimated_total_items(self, details: dict) -> int:
        """安全获取预估总 item 数"""
        try:
            count = int(details.get("count", 0) or 0)
            folder_count = int(details.get("folder_count", 0) or 0)
            return max(0, count + folder_count)
        except (ValueError, TypeError):
            return 0
    def _get_original_folder_name_from_paths(self) -> str:
        """从当前目录的 paths 信息中提取原始业务目录名（忽略分页前缀）"""
        if not self.state.current_folder_id or self.state.current_folder_id == '0':
            return "Root"
        # 获取当前目录的详情（含 paths）
        details = self.api_service.get_item_details(self.state.current_folder_id)
        if not details or not isinstance(details, dict):
            # fallback to title
            return self.state.title.replace("Folder '", "").replace("' List", "").strip()
        paths = details.get("paths", [])
        if not paths or not isinstance(paths, list):
            return "Unknown"
        # 从 paths 中提取所有非根目录名
        folder_names = []
        for p in paths:
            name = _get_item_attribute(p, "file_name")
            if name and name not in ["Root", "0"]:
                folder_names.append(name)
        if not folder_names:
            return "Unknown"
        # 取最后一个（即当前目录的直接父业务目录）
        raw_name = folder_names[-1]
        # 剥离可能的分页标记（如 [1/2]、分组、块等）
        import re
        # 移除 [1/2] 前缀
        cleaned = re.sub(r'^\[\d+/\d+\]\s*', '', raw_name)
        # 移除分组/块后缀
        cleaned = re.sub(r'\s*[-—]\s*(分组\d+（共\d+组）|块\d+（\d+-\d+）)$', '', cleaned)
        return cleaned.strip() or raw_name        
    def _command_page2(self, action_choice: str = "", page_items: List[Dict] = None) -> str:
        # Step 1: 执行 a
        logging.info("page2: 正在执行 'a' 命令以获取全部项目...")
        self._command_a()
        all_items = self.state._all_items_cache
        if not all_items:
            logging.warning("page2: 当前上下文无任何项目，无法分页。")
            return CMD_CONTINUE_INPUT
        # Step 2: ✅ 从 paths 中提取干净原始名（不再依赖 title！）
        original_name = self._get_original_folder_name_from_paths()
        logging.debug(f"page2: 从路径信息中提取的原始名称为: '{original_name}'")
        total_items = len(all_items)
        GROUP_SIZE = 200
        total_groups = (total_items + GROUP_SIZE - 1) // GROUP_SIZE
        current_cid = self.state.current_folder_id
        if not current_cid:
            logging.error("page2: 无法获取当前目录 CID，操作终止。")
            return CMD_CONTINUE_INPUT
        logging.info(f"page2: 共 {total_items} 个项目，将分为 {total_groups} 组，每组最多 {GROUP_SIZE} 项。")
        # Step 2: 按组处理
        for group_idx in range(total_groups):
            start = group_idx * GROUP_SIZE
            end = min(start + GROUP_SIZE, total_items)
            group_items = all_items[start:end]
            # 提取 fid 列表（仅保留有效 fid）
            fids_to_move = extract_fids(group_items)
            if not fids_to_move:
                logging.warning(f"page2: 第{group_idx + 1}组无有效项目，跳过。")
                continue
            # 创建分页文件夹
            start_num = start + 1
            end_num = min(start + GROUP_SIZE, total_items)
            folder_name = f"[2/2] {original_name} - 块{group_idx+1:03d}（{start_num}-{end_num}）"
            logging.info(f"page2: 正在创建分页文件夹: {folder_name}")
            new_cid, _, err = self.api_service.create_folder(current_cid, folder_name)
            if not new_cid:
                logging.error(f"page2: 无法创建分页文件夹 '{folder_name}'，跳过该组。")
                continue
            # 执行基本移动（不递归、不智能）
            logging.info(f"page2: 正在移动第{group_idx + 1}组（{len(fids_to_move)} 项）到 '{folder_name}'...")
            success = self.api_service.move_files(fids_to_move, new_cid)
            if success:
                logging.info(f"✅ 第{group_idx + 1}组移动成功。")
            else:
                logging.error(f"❌ 第{group_idx + 1}组移动失败！")
            # 速率控制：休眠时间基于文件数量
            sleep_time = 100000 / self.config.MOVE_RATE_LIMIT_FILES_PER_SECOND + 10
            logging.info(f"Rate limiting: sleeping {sleep_time:.2f} seconds...")
            time.sleep(sleep_time)
        logging.info("✨ page2 分页归档操作全部完成！")
        self.state._last_fetched_params_hash = None
        return CMD_RENDER_NEEDED
    def _download_item_handler(self, item: Dict, recursion_level: int, base_download_path: str, current_relative_path: str, all_items_collector: List[Tuple[Dict, str]]):
        item_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown Item")
        file_relative_path = join_relative_path(current_relative_path, item_name)
        full_target_path_for_file = os.path.join(base_download_path, file_relative_path)
        all_items_collector.append((item, full_target_path_for_file))
        logging.debug(f"{'  ' * recursion_level}Collected file for download: {file_relative_path}.")
    def _json_collection_item_handler(self, item: Dict, recursion_level: int, all_items_collector: List[Dict], current_relative_path: str = "", **kwargs):
        item_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown Item")
        full_path = join_relative_path(current_relative_path, item_name)
        item["_relative_path"] = full_path
        item_id = _get_item_attribute(item, "fid", "file_id")
        if item_id:
            all_items_collector.append(item)
            logging.debug(f"{'  ' * recursion_level}Collected: {full_path}")
        else:
            logging.warning(f"{'  ' * recursion_level}Skipping item without ID: {full_path}")
    def _download_folder_handler(self, folder: Dict, recursion_level: int, base_download_path: str, current_relative_path: str, **kwargs):
        folder_name = _get_item_attribute(folder, "fn", "file_name", default_value="Unknown Folder")
        folder_relative_path = join_relative_path(current_relative_path, folder_name)
        full_folder_path = os.path.join(base_download_path, folder_relative_path)
        logging.debug(f"{'  ' * recursion_level}Will create directory: {folder_relative_path}")
    def _create_download_directories(self, files_to_download: List[Tuple[Dict, str]]):
        directories_created = set()
        for item, full_file_path in files_to_download:
            file_dir = os.path.dirname(full_file_path)
            if file_dir not in directories_created:
                try:
                    os.makedirs(file_dir, exist_ok=True)
                    directories_created.add(file_dir)
                    logging.debug(f"Created directory: {file_dir}")
                except OSError as e:
                    logging.error(f"Failed to create directory {file_dir}: {e}")
    def recursively_download_folder(self, folder_info: Dict, current_download_path: str, prefix_item_name: str = "Current Task"):
        folder_id = _get_item_attribute(folder_info, "fid", "file_id")
        folder_name = _get_item_attribute(folder_info, "fn", "file_name", default_value="Unknown Folder")
        logging.debug(f"Starting recursive file collection for folder '{folder_name}' (ID: '{folder_id}') to path: '{current_download_path}'")
        os.makedirs(current_download_path, exist_ok=True)
        all_files_to_download = []
        self._generic_traverse_folder_items_concurrent(
            root_cid=folder_id,
            item_handler_func=self._download_item_handler,
            folder_handler_func=self._download_folder_handler,
            base_kwargs={
            'base_download_path': current_download_path,
            'current_relative_path': "",
            'all_items_collector': all_files_to_download,
            },
            processed_cids=set()
        )
        logging.debug(f"File collection for folder '{folder_name}' completed, found {len(all_files_to_download)} files.")
        if all_files_to_download:
            self._create_download_directories(all_files_to_download)
            self._execute_download_queue(
                all_files_to_download,
                prefix_item_name=folder_name
            )
        else:
            logging.debug(f"No downloadable files found in folder '{folder_name}'.")
    def _command_d(self, action_choice: str, page_items: List[Dict]) -> str:
        indices_str = action_choice.split(' ', 1)[1]
        selected_indices = parse_indices_input(indices_str, len(page_items))
        if selected_indices is None or not selected_indices:
            logging.warning("Invalid download index selection.")
            return CMD_CONTINUE_INPUT
        files_to_download_immediately = []
        folders_to_process = []
        for index in selected_indices:
            item = page_items[index]
            if is_item_folder(item):
                folders_to_process.append(item)
            else:
                file_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown File")
                full_target_path = os.path.join(self.state.target_download_dir, file_name)
                files_to_download_immediately.append((item, full_target_path))
        if files_to_download_immediately:
            logging.debug(f"Starting download of {len(files_to_download_immediately)} individual files.")
            self._execute_download_queue(
                files_to_download_immediately,
                prefix_item_name="Individual File Download"
            )
        if folders_to_process:
            for idx, folder in enumerate(folders_to_process):
                folder_name = _get_item_attribute(folder, "fn", "file_name", default_value="Unknown Folder")
                recursive_download_path = os.path.join(self.state.target_download_dir, folder_name)
                self.recursively_download_folder(
                    folder_info=folder,
                    current_download_path=recursive_download_path,
                    prefix_item_name=folder_name
                )
                logging.info(f"--- Folder '{folder_name}' processing completed ---")
        return CMD_RENDER_NEEDED
    def _command_v(self, action_choice: str, page_items: List[Dict]) -> str:
        try:
            indices_str = action_choice.split(' ', 1)[1]
        except IndexError:
            logging.warning("Please provide item index(es) for 'v' command (e.g., 'v 0' or 'v 0,1').")
            return CMD_CONTINUE_INPUT
        selected_indices = parse_indices_input(indices_str, len(page_items))
        if not selected_indices:
            logging.warning("No valid items selected. Please provide valid index(es).")
            return CMD_CONTINUE_INPUT
        valid_selected_items_with_info = []
        for idx in selected_indices:
            item = page_items[idx]
            if is_item_folder(item):
                file_name = _get_item_attribute(item, 'fn', 'file_name', default_value="Unknown Folder")
                logging.info(f"Skipping folder at index {idx}: '{file_name}', cannot play.")
                continue
            if not _get_item_attribute(item, "fid", "file_id"):
                file_name = _get_item_attribute(item, 'fn', 'file_name', default_value="Unknown File")
                logging.warning(f"Item at index {idx} ('{file_name}') lacks a valid ID, skipping.")
                continue
            valid_selected_items_with_info.append((idx, item))
        if not valid_selected_items_with_info:
            logging.warning("All selected items are folders or lack valid IDs. No files to process for playback.")
            return CMD_CONTINUE_INPUT
        if self.config.DEFAULT_PLAYBACK_STRATEGY == 1:
            for original_idx, item_data in valid_selected_items_with_info:
                file_name = _get_item_attribute(item_data, "fn", "file_name", default_value="未知文件")
                logging.info(f"准备播放文件：'{file_name}'。正在获取其下载链接...")
                try:
                    download_url_candidate, _, _ = self.api_service.get_download_link_details(item_data)
                    if download_url_candidate:
                        if file_name.lower().endswith('.iso'):
                            self._play_with_infuse(download_url_candidate, file_name)
                        else:
                            self._play_with_mpv(download_url_candidate, file_name)
                except Exception as exc:
                    logging.error(f"获取 '{file_name}' 下载链接或播放时发生错误：{exc}")
            return CMD_RENDER_NEEDED
        elif self.config.DEFAULT_PLAYBACK_STRATEGY == 2:
            for original_idx, item_data in valid_selected_items_with_info:
                file_name = _get_item_attribute(item_data, "fn", "file_name", default_value="未知文件")
                logging.info(f"准备播放文件：'{file_name}'。正在获取其下载链接...")
                try:
                    download_url_candidate, _, _ = self.api_service.get_download_link_details(item_data)
                    if download_url_candidate:
                        self._play_with_infuse(download_url_candidate, file_name)
                except Exception as exc:
                    logging.error(f"获取 '{file_name}' 下载链接或播放时发生错误：{exc}")
            return CMD_RENDER_NEEDED
    # ============ 优化后的 _command_i =============
    def _command_i(self, action_choice: str, page_items: List[Dict]) -> str:
        indices_str = action_choice.split(' ', 1)[1]
        selected_indices = parse_indices_input(indices_str, len(page_items))
        if not selected_indices:
            logging.warning("No items selected to query for details.")
            return CMD_CONTINUE_INPUT
        items_to_fetch_details = [(idx, page_items[idx]) for idx in selected_indices if _get_item_attribute(page_items[idx], "fid", "file_id")]
        if not items_to_fetch_details:
            logging.warning("Selected items lack valid IDs, cannot fetch details.")
            return CMD_CONTINUE_INPUT
        logging.info(f"Fetching details for {len(items_to_fetch_details)} items.")

        # === 使用 ApiService 的批量获取方法 ===
        fids = extract_fids([item for _, item in items_to_fetch_details])
        details_map = self.api_service.get_items_details_batch(fids)
        
        # 注入详情
        for idx, item in items_to_fetch_details:
            fid = _get_item_attribute(item, "fid", "file_id")
            details = details_map.get(fid)
            if details:
                page_items[idx]['_details'] = details
                logging.info(f"Successfully retrieved details for item at index {idx}.")
            else:
                logging.warning(f"Failed to retrieve details for item at index {idx}.")
        logging.info("Detail fetching completed for all selected items.")
        self.state._force_full_display_next_render = True
        return CMD_RENDER_NEEDED
    def _command_a(self) -> str:
        logging.debug(f"You have chosen to retrieve all items for {self.state.title}.")
        total_to_fetch = self.state.explorable_count
        fetch_limit_for_all = self.config.API_FETCH_LIMIT
        main_param_name = 'cid' if self.state.current_fetch_function == self.api_service.fetch_files_in_directory_page else 'search_value'
        all_items_fetched = self.api_service._fetch_all_items_general(
            fetch_function=self.state.current_fetch_function,
            base_fetch_kwargs=self.state.current_browse_params,
            total_count=total_to_fetch,
            page_size=fetch_limit_for_all,
            main_id_param_name=main_param_name
        )
        self.state._all_items_cache = all_items_fetched
        self.state.total_items = len(all_items_fetched)
        self.state.explorable_count = self.state.total_items
        self.state.paginator_display_size = self.state.total_items if self.state.total_items > 0 else 1
        self.state.current_offset = 0
        self.state.showing_all_items = True
        self.state.title = f"{self.state.title} All Items List"
        return CMD_RENDER_NEEDED
    def _command_b(self) -> str:
        if self.state.parent_cid_stack:
            prev_state = self.state.parent_cid_stack.pop()
            self.state.restore_from_snapshot(prev_state)
            logging.debug(f"Restored to parent state. Title: {self.state.title}, CID: {_get_item_attribute(self.state.current_browse_params, 'cid', default_value='N/A')}.")
            return CMD_RENDER_NEEDED
        else:
            logging.info("You are already at the root directory.")
            return CMD_RENDER_NEEDED
    def _command_g(self, action_choice: str, *args) -> str:
        if self.state.showing_all_items:
            logging.warning("Currently displaying all items, pagination not supported.")
            return CMD_CONTINUE_INPUT
        try:
            target_page = int(action_choice.split(' ')[1])
            total_display_pages = (self.state.explorable_count + self.config.PAGINATOR_DISPLAY_SIZE - 1) // self.config.PAGINATOR_DISPLAY_SIZE if self.config.PAGINATOR_DISPLAY_SIZE > 0 else 1
            if 1 <= target_page <= total_display_pages:
                self.state.current_offset = (target_page - 1) * self.config.PAGINATOR_DISPLAY_SIZE
                self.state.current_display_page = target_page
                return CMD_RENDER_NEEDED
            else:
                logging.warning(f"Invalid page number '{target_page}'. Page number should be between 1 and {total_display_pages}.")
                return CMD_CONTINUE_INPUT
        except (ValueError, IndexError):
            logging.warning("Incorrect command format, please use 'g <page_number>'.")
            return CMD_CONTINUE_INPUT
    def _command_p(self) -> str:
        if self.state.showing_all_items:
            logging.warning("Currently displaying all items, pagination not supported.")
            return CMD_CONTINUE_INPUT
        self.state.current_offset = max(0, self.state.current_offset - self.config.PAGINATOR_DISPLAY_SIZE)
        return CMD_RENDER_NEEDED
    def _command_n(self) -> str:
        if self.state.showing_all_items:
            logging.warning("Currently displaying all items, pagination not supported.")
            return CMD_CONTINUE_INPUT
        potential_next_offset = self.state.current_offset + self.config.PAGINATOR_DISPLAY_SIZE
        last_page_start_offset = max(0, (self.state.explorable_count - 1) // self.config.PAGINATOR_DISPLAY_SIZE * self.config.PAGINATOR_DISPLAY_SIZE)
        if potential_next_offset <= last_page_start_offset:
            self.state.current_offset = potential_next_offset
        else:
            logging.info("Already on the last page, or no more content.")
            self.state.current_offset = last_page_start_offset
        return CMD_RENDER_NEEDED
    def _command_t(self) -> str:
        self.config.show_list_short_form = not self.config.show_list_short_form
        mode_text = "Compact mode (name only)" if self.config.show_list_short_form else "Full mode (all details)"
        logging.info(f"Display mode toggled to: {mode_text}.")
        return CMD_RENDER_NEEDED
    def _command_mc(self) -> str:
        self.config.enable_concurrent_c_details_fetching = not self.config.enable_concurrent_c_details_fetching
        status_text = "Enabled" if self.config.enable_concurrent_c_details_fetching else "Disabled"
        logging.info(f"Concurrent detail fetching for 'c' command is now {status_text}.")
        return CMD_CONTINUE_INPUT
    def _command_f(self, action_choice: str, *args) -> str:
        search_keyword = action_choice.split(' ', 1)[1].strip()
        if not search_keyword:
            logging.warning("Please enter a valid search keyword.")
            return CMD_CONTINUE_INPUT
        logging.info(f"Searching for: '{search_keyword}'.")
        self.state.parent_cid_stack.append(self.state.create_snapshot())
        self.state.current_fetch_function = self.api_service.search_files
        search_fetch_kwargs = {"search_value": search_keyword}
        search_fetch_kwargs["cid"] = self.state.current_folder_id
        if self.config.search_more_query:
            fc_input = _get_user_input("Filter by type (1: folders only, 2: files only, default: all)",
                                        current_value=str(_get_item_attribute(search_fetch_kwargs, 'fc', default_value='')))
            if fc_input in ['1', '2']:
                search_fetch_kwargs['fc'] = fc_input
            elif fc_input:
                logging.warning(f"Invalid 'fc' input: '{fc_input}'. Skipping filter.")
            type_input = _get_user_input("Filter by category (1: documents, 2: pictures, 3: music, 4: videos, 5: compressed, 6: applications, default: all)",
                                         current_value=str(_get_item_attribute(search_fetch_kwargs, 'type', default_value='')))
            if type_input in ['1', '2', '3', '4', '5', '6']:
                search_fetch_kwargs['type'] = type_input
            elif type_input:
                logging.warning(f"Invalid 'type' input: '{type_input}'. Skipping filter.")
            suffix_input = _get_user_input("Filter by file extension (e.g.: 'mp4', 'pdf', default: all)",
                                           current_value=str(_get_item_attribute(search_fetch_kwargs, 'suffix', default_value='')))
            if suffix_input:
                search_fetch_kwargs['suffix'] = suffix_input
            search_cid_input = _get_user_input("Search in directory (CID, '0' for all)",
                                                current_value=str(_get_item_attribute(search_fetch_kwargs, 'cid', default_value=self.state.current_folder_id)))
            search_fetch_kwargs['cid'] = search_cid_input
        self.state.current_browse_params = search_fetch_kwargs.copy()
        self.state.current_offset = 0
        self.state.showing_all_items = False
        self.state.title = f"Search Results: '{search_keyword}'"
        self.state._last_fetched_params_hash = None
        return CMD_RENDER_NEEDED
    def _command_page1(self, action_choice: str, page_items: List[Dict]) -> str:
        # Step 1: 执行 a
        logging.info("page1: 正在执行 'a' 命令以获取全部项目...")
        self._command_a()
        # 获取当前目录名称
        if self.state.current_folder_id == '0':
            current_folder_name = "Root"
        else:
            folder_info = self.api_service.get_item_details(self.state.current_folder_id)
            if folder_info and isinstance(folder_info, dict):
                current_folder_name = folder_info.get("file_name", "Unknown")
            else:
                current_folder_name = "Unknown"
        # Step 1: 收集当前页所有子文件夹（只处理文件夹）
        folder_items = []
        for item in self.state._all_items_cache:
            if is_item_folder(item):
                fid = _get_item_attribute(item, "fid", "file_id")
                name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown")
                if fid and name:
                    folder_items.append((fid, name, item))
        if not folder_items:
            logging.warning("当前目录下没有子文件夹，无法分页。")
            return CMD_CONTINUE_INPUT
        # Step 2: 获取每个文件夹的 count + folder_count（使用统一并发函数）===
        fids = [fid for fid, _, _ in folder_items]
        details_map = self.api_service.get_items_details_batch(fids)
        folder_stats = []
        for (fid, name, _), details in zip(folder_items, [details_map.get(fid) for fid in fids]):
            if details:
                total = self._get_estimated_total_items(details)
                folder_stats.append((fid, name, total))
        # Step 3: 贪心分组（First Fit Decreasing - 正确实现）
        MAX_LIMIT = 100000
        folder_stats.sort(key=lambda x: x[2], reverse=True)  # 从大到小排序
        groups = []  # 每个元素: [item_list, current_sum]
        for fid, name, total in folder_stats:
            # 尝试放入已存在的组（First Fit）
            placed = False
            for group in groups:
                if group[1] + total <= MAX_LIMIT:
                    group[0].append((fid, name, total))
                    group[1] += total
                    placed = True
                    break
            if not placed:
                # 所有组都放不下，新建组
                groups.append([[(fid, name, total)], total])
        if not groups:
            logging.warning("无法生成任何有效分组。")
            return CMD_CONTINUE_INPUT
        # Step 4: 为每组创建新分页文件夹并移动
        current_cid = self.state.current_folder_id
        for idx, (group_items, _) in enumerate(groups, start=1):
            new_folder_name = f"[1/2] {current_folder_name} - 分组{idx}（共{len(groups)}组）"
            new_cid, _, err = self.api_service.create_folder(current_cid, new_folder_name)
            if not new_cid:
                logging.error(f"❌ 无法创建分页文件夹 '{new_folder_name}'，跳过该组。")
                continue
            logging.info(f"📁 创建分页文件夹: {new_folder_name} (ID: {new_cid})")
            fids_to_move = [fid for fid, _, _ in group_items]
            logging.info(f"📁 正在移动 {len(fids_to_move)} 个文件夹到分页文件夹 (ID: {new_cid})...")
            success = self.api_service.move_files(fids_to_move, new_cid)
            if success:
                logging.info(f"✅ 分页-{idx} 完成，共移动 {len(fids_to_move)} 个文件夹。")
            else:
                logging.warning(f"⚠️ 分页-{idx} 移动失败！")
                # 速率控制：休眠时间基于文件数量
            sleep_time = 100000 / self.config.MOVE_RATE_LIMIT_FILES_PER_SECOND + 10
            logging.info(f"Rate limiting: sleeping {sleep_time:.2f} seconds...")
            time.sleep(sleep_time)
        logging.info("✨ 分页归档操作完成！")
        self.state._last_fetched_params_hash = None
        return CMD_RENDER_NEEDED
    def _command_s(self) -> str:
        logging.info("\n--- Adjust Browse Parameters ---")
        self.state.parent_cid_stack.append(self.state.create_snapshot())
        new_s_params = {}
        new_s_params['cid'] = str(_get_item_attribute(self.state.current_browse_params.copy(), 'cid', default_value=self.config.ROOT_CID))
        new_s_params['custom_order'] = 1
        DEFAULT_S_PARAMS = {
            "o": "file_size",
            "asc": "0",
            "type": "",
            "suffix": "",
        }
        print("\nAdjust browse parameters:")
        filter_prompts = [
            ("o", "Sort by (1:File Name, 2:File Size, 3:Last Updated, 4:File Type)", ["1", "2", "3", "4", ""]),
            ("asc", "Sort direction (1: Ascending, 0: Descending)", ["0", "1", ""]),
            ("type", "File Type (1:documents;2:pictures;3:music;4:videos;5:compressed;6:applications;7:books)", ["1", "2", "3", "4", "5", "6", "7", ""]),
            ("suffix", "File Extension (e.g.: 'mp4', 'pdf', default: all)", None),
        ]
        for param_name, prompt_text, valid_values in filter_prompts:
            default_val = DEFAULT_S_PARAMS.get(param_name, "")
            if param_name == "o":
                print("\nSelect sort method:")
                sort_labels = {
                    "1": "File Name",
                    "2": "File Size",
                    "3": "Last Updated",
                    "4": "File Type"
                }
                for key, label in sort_labels.items():
                    print(f"[{key}] {label}")
                default_o_option = "2"
                for opt, field in {"1": "file_name", "2": "file_size", "3": "user_utime", "4": "file_type", "5": ""}.items():
                    if field == default_val:
                        default_o_option = opt
                        break
                user_input = _get_user_input(
                    "Enter sort option number",
                    current_value=default_o_option,
                    valid_values=valid_values
                )
                o_mapping = {"1": "file_name", "2": "file_size", "3": "user_utime", "4": "file_type", "5": ""}
                if user_input in o_mapping:
                    new_s_params["o"] = o_mapping[user_input]
                elif user_input == "":
                    new_s_params["o"] = default_val
                if new_s_params.get("o") == "":
                    if "asc" in new_s_params:
                        del new_s_params["asc"]
            elif param_name == "asc":
                if new_s_params.get("o") != "":
                    user_input = _get_user_input(
                        prompt_text,
                        current_value=DEFAULT_S_PARAMS["asc"],
                        valid_values=valid_values
                    )
                    if user_input == "":
                        new_s_params["asc"] = DEFAULT_S_PARAMS["asc"]
                    else:
                        new_s_params["asc"] = user_input
            else:
                user_input = _get_user_input(
                    prompt_text,
                    current_value=default_val,
                    valid_values=valid_values
                )
                if user_input == "":
                    if default_val != "":
                        new_s_params[param_name] = default_val
                else:
                    new_s_params[param_name] = user_input
        self.state.current_browse_params = new_s_params.copy()
        logging.debug(f"Updated browse parameters: {self.state.current_browse_params}")
        self.state.current_offset = 0
        self.state.showing_all_items = False
        self.state.title = f"Filtered list for directory '{_get_item_attribute(new_s_params, 'cid', default_value=self.config.ROOT_CID)}'"
        self.state._last_fetched_params_hash = None
        return CMD_RENDER_NEEDED
    def _command_index_selection(self, action_choice: str, page_items_to_display: List[Dict]) -> str:
        selected_indices = parse_indices_input(action_choice, len(page_items_to_display))
        if selected_indices is None:
            logging.info("Operation cancelled.")
            return CMD_CONTINUE_INPUT
        if not selected_indices and action_choice.lower() in ['a', 'all'] and not page_items_to_display:
            logging.warning("Current list is empty, cannot perform 'a' / 'all' operation.")
            return CMD_CONTINUE_INPUT
        if not selected_indices and action_choice.lower() not in ['a', 'all']:
            logging.warning("Invalid selection, please re-enter.")
            return CMD_CONTINUE_INPUT
        if len(selected_indices) == 1 and is_item_folder(page_items_to_display[selected_indices[0]]):
            item_index = selected_indices[0]
            selected_item = page_items_to_display[item_index]
            logging.debug(f"You selected folder '{_get_item_attribute(selected_item, 'fn', 'file_name', default_value='Unknown Folder')}' (ID: {_get_item_attribute(selected_item, 'fid', 'file_id', default_value='Unknown ID')}), retrieving its contents.")
            self.state.parent_cid_stack.append(self.state.create_snapshot())
            self.state.current_fetch_function = self.api_service.fetch_files_in_directory_page
            current_fetch_kwargs_subfolder = self.config.COMMON_BROWSE_FETCH_PARAMS.copy()
            current_fetch_kwargs_subfolder["cid"] = _get_item_attribute(selected_item, "fid", "file_id", default_value=self.config.ROOT_CID)
            self.state.current_browse_params = current_fetch_kwargs_subfolder.copy()
            self.state.total_items = 0
            self.state.explorable_count = 0
            self.state.current_offset = 0
            self.state.showing_all_items = False
            self.state.folder_name=_get_item_attribute(selected_item, 'fn', 'file_name', default_value='Unknown Folder')
            self.state.title = f"Folder '{_get_item_attribute(selected_item, 'fn', 'file_name', default_value='Unknown Folder')}' List"
            self.state._last_fetched_params_hash = None
            self.state.current_folder_id = _get_item_attribute(current_fetch_kwargs_subfolder, "cid", default_value=self.config.ROOT_CID)
            logging.debug(f"DEBUG: After folder selection, self.state.current_browse_params is: {self.state.current_browse_params}")
            return CMD_RENDER_NEEDED
        else:
            logging.debug(f"You selected item(s) {selected_indices}, displaying their details.")
            self._display_selected_items_details(selected_indices, page_items_to_display)
            return CMD_CONTINUE_INPUT
    def _display_selected_items_details(self, selected_indices: List[int], page_items: List[Dict]):
        if not selected_indices:
            logging.warning("No items selected to display details.")
            return
        logging.info(f"\n--- Details for {len(selected_indices)} selected item(s) ---")
        for index in selected_indices:
            if 0 <= index < len(page_items):
                item = page_items[index]
                item_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown")
                item_type = "Folder" if is_item_folder(item) else "File"
                item_id = _get_item_attribute(item, "fid", "file_id", default_value="N/A")
                item_size = _get_item_attribute(item, "fs", "file_size", default_value="N/A")
                logging.info(f"\n[{index}] {item_name} ({item_type})")
                logging.info(f"    ID: {item_id}")
                if not is_item_folder(item) and item_size != "N/A":
                    try:
                        size_readable = format_bytes_to_human_readable(int(item_size))
                        logging.info(f"    Size: {size_readable}")
                    except (ValueError, TypeError):
                        logging.info(f"    Size: {item_size}")
                if item.get('_details'):
                    details = item['_details']
                    logging.info("    Additional Details:")
                    if is_item_folder(item):
                        folder_size = _get_item_attribute(details, "size", default_value="N/A")
                        file_count = _get_item_attribute(details, "count", default_value="N/A")
                        folder_count = _get_item_attribute(details, "folder_count", default_value="N/A")
                        logging.info(f"        Folder Size: {folder_size}")
                        logging.info(f"        File Count: {file_count}")
                        logging.info(f"        Folder Count: {folder_count}")
                    paths = _get_item_attribute(details, "paths")
                    if paths and isinstance(paths, list) and len(paths) > 0:
                        path_segments = [_get_item_attribute(p, "file_name", default_value="") for p in paths if _get_item_attribute(p, "file_name")]
                        full_path = "/" + "/".join(path_segments + [item_name]) if path_segments else f"/{item_name}"
                        logging.info(f"        Path: {full_path}")
                if not is_item_folder(item):
                    pick_code = _get_item_attribute(item, "pc", "pick_code", default_value="N/A")
                    logging.info(f"    Pick Code: {pick_code}")
            else:
                logging.warning(f"Index {index} is out of range.")
        logging.info("--- End of Details ---")
    def _command_h(self):
        self.ui_renderer.display_help()
    def _command_save(self, action_choice: str, page_items: List[Dict]) -> str:
        user_input_parts = action_choice.split()
        if len(user_input_parts) < 2:
            logging.warning("Usage: save <filename.json> [a].")
            return CMD_CONTINUE_INPUT
        filename = user_input_parts[1]
        if not filename.endswith('.json'):
            filename += '.json'
        json_output_dir = os.path.join(self.config.DEFAULT_TARGET_DOWNLOAD_DIR, self.config.JSON_OUTPUT_SUBDIR)
        output_filepath = os.path.join(json_output_dir, filename)
        items_to_save = []
        if len(user_input_parts) > 2 and user_input_parts[2].lower() == 'a':
            logging.info("Retrieving all items to save to JSON file.")
            main_param_name = 'cid' if self.state.current_fetch_function == self.api_service.fetch_files_in_directory_page else 'search_value'
            items_to_save = self.api_service._fetch_all_items_general(
                fetch_function=self.state.current_fetch_function,
                base_fetch_kwargs=self.state.current_browse_params,
                total_count=self.state.explorable_count,
                page_size=self.config.API_FETCH_LIMIT,
                main_id_param_name=main_param_name
            )
        else:
            items_to_save = self.state.get_current_display_items()
            logging.info("Saving current page items to JSON file.")
        # === 新增：根据 mc 开关决定是否获取 _details ===
        if self.config.enable_concurrent_c_details_fetching and items_to_save:
            logging.info(f"Fetching detailed info for {len(items_to_save)} items (controlled by 'mc' setting)...")
            fids = extract_fids(items_to_save)
            if fids:
                details_map = self.api_service.get_items_details_batch(fids)
                for item in items_to_save:
                    fid = _get_item_attribute(item, "fid", "file_id")
                    if fid and fid in details_map:
                        item['_details'] = details_map[fid]
        save_json_output(items_to_save, output_filepath)
        return CMD_CONTINUE_INPUT
    def _command_m(self, action_choice: str, page_items: List[Dict]) -> str:
        user_input_parts = action_choice.split()
        if len(user_input_parts) < 2:
            logging.warning("Usage: m <index1,index2-index3,...> or m a.")
            return CMD_CONTINUE_INPUT
        indices_str = user_input_parts[1]
        current_page_items = page_items
        selected_indices = parse_indices_input(indices_str, len(current_page_items))
        if selected_indices is None:
            logging.warning("Invalid index input.")
            return CMD_CONTINUE_INPUT
        if not current_page_items:
            logging.warning("No selectable items on current page.")
            return CMD_CONTINUE_INPUT
        for index in selected_indices:
            if 0 <= index < len(current_page_items):
                item = current_page_items[index]
                file_id = _get_item_attribute(item, "fid", "file_id")
                file_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown File")
                if file_id and file_id not in self.state.marked_for_move_file_ids:
                    self.state.marked_for_move_file_ids.append(file_id)
                    #logging.debug(f"Marked '{file_name}' (ID: {file_id}) for moving.")
                    #logging.info(f"Marked '{len(self.state.marked_for_move_file_ids)} items'  for moving.")
                elif file_id and file_id in self.state.marked_for_move_file_ids:
                    logging.info(f"'{file_name}' (ID: {file_id}) is already in the marked list.")
            else:
                logging.warning(f"Index {index} is out of current page range.")
        return CMD_RENDER_NEEDED
    def _command_mm(self) -> str:
        if not self.state.marked_for_move_file_ids:
            logging.warning("No marked files/folders to move. Please mark files using 'm <index>' first.")
            return CMD_CONTINUE_INPUT
        target_cid = self.state.current_folder_id
        if not target_cid:
            logging.error("Could not determine current directory CID. Cannot perform move operation.")
            return CMD_CONTINUE_INPUT
        confirm = input(f"Confirm moving {len(self.state.marked_for_move_file_ids)} file(s)/folder(s) to current directory (ID: {target_cid})? (y/n): ").strip().lower()
        if confirm == 'y':
            success = self.api_service.move_files(self.state.marked_for_move_file_ids, target_cid)
            if success:
                _log_move_operation(self.state.marked_for_move_file_ids, target_cid, self.config)
                logging.info(f"Successfully moved {len(self.state.marked_for_move_file_ids)} file(s)/folder(s).")
                self.state._last_fetched_params_hash = None
                self.state.current_offset = 0
                self.state.marked_for_move_file_ids = []
                return CMD_RENDER_NEEDED
            else:
                logging.error("Move operation failed. Please check logs.")
                return CMD_CONTINUE_INPUT
        else:
            logging.info("Move operation cancelled.")
            return CMD_CONTINUE_INPUT
    def _smart_merge_items(self, source_items: List[Dict], target_cid: str) -> Tuple[bool, int, int]:
        """
        智能合并：先按目标 CID 分组，再批量移动（若不超过限制）
        """
        MAX_ITEMS = self.config.MOVE_MAX_FILE_IDS
        RATE_LIMIT = self.config.MOVE_RATE_LIMIT_FILES_PER_SECOND
        # Step 1: 为每个 source_item 确定其“最终目标 CID”和预估数量
        item_targets = []  # (fid, final_target_cid, est_count, is_folder)
        target_dir_cache = {}
        for item in source_items:
            fid = _get_item_attribute(item, "fid", "file_id")
            name = _get_item_attribute(item, "fn", "file_name")
            is_folder = is_item_folder(item)
            if not fid or not name:
                continue
            if not is_folder:
                item_targets.append((fid, target_cid, 1, False))
                continue
            # 是文件夹
            details = self.api_service.get_item_details(fid)
            if not details:
                continue
            total_est = self._get_estimated_total_items(details)
            # 检查目标是否存在同名文件夹
            cache_key = ('folders', target_cid)
            if cache_key not in target_dir_cache:
                target_dir_cache[cache_key] = self._list_folders_in_cid(target_cid)
            target_folders = target_dir_cache[cache_key]
            name_lower = name.lower()
            if name_lower in target_folders:
                # 存在：目标为 existing_cid，需递归合并（不能批量）
                existing_cid = target_folders[name_lower]
                item_targets.append((fid, existing_cid, total_est, True))
            else:
                # 不存在：目标为新创建的 cid（但先不创建，留到分组后统一处理）
                item_targets.append((fid, target_cid, total_est, True))
        # Step 2: 按 final_target_cid 分组
        groups = {}
        for fid, tgt_cid, est, is_folder in item_targets:
            groups.setdefault(tgt_cid, []).append((fid, est, is_folder))
        success_count = 0
        fail_count = 0
        fatal_error = False
        # Step 3: 处理每组
        for tgt_cid, items in groups.items():
            total_est_group = sum(est for _, est, _ in items)
            fids_group = [fid for fid, _, _ in items]
            has_folder = any(is_folder for _, _, is_folder in items)
            if total_est_group <= MAX_ITEMS and not has_folder:
                # 全是文件 or 小文件夹，且总量不超限 → 批量移动
                logging.info(f"Merging {len(fids_group)} items to CID {tgt_cid} in one call.")
                if self.api_service.move_files(fids_group, tgt_cid):
                    success_count += len(fids_group)
                else:
                    fail_count += len(fids_group)
                sleep_time = total_est_group / RATE_LIMIT
                if sleep_time > 0:
                    logging.info(f"Rate limiting: sleeping {sleep_time:.2f} seconds...")
                    time.sleep(sleep_time)
            else:
                # 需要递归处理（含文件夹或超限）
                # 构造 fake items for _smart_move_recursive
                fake_items = []
                for fid, _, _ in items:
                    # 从原 source_items 找回完整 item
                    orig_item = next((it for it in source_items if _get_item_attribute(it, "fid", "file_id") == fid), None)
                    if orig_item:
                        fake_items.append(orig_item)
                if fake_items:
                    no_fatal, sub_success, sub_fail = self._smart_move_recursive(fake_items, tgt_cid, target_dir_cache)
                    if not no_fatal:
                        fatal_error = True
                    success_count += sub_success
                    fail_count += sub_fail
        return (not fatal_error), success_count, fail_count
    def _command_merge(self) -> str:
        if not self.state.marked_for_move_file_ids:
            logging.warning("No marked files/folders to merge. Please mark files using 'm <index>' first.")
            return CMD_CONTINUE_INPUT
        target_cid = self.state.current_folder_id
        if not target_cid:
            logging.error("Could not determine current directory CID.")
            return CMD_CONTINUE_INPUT
        # === Step 1: 缓存目标目录的一级子项（文件 + 文件夹）===
        logging.info("Fetching existing items in target directory for merge resolution...")
        existing_target_items = {}  # {name_lower: (fid, is_folder)}
        offset = 0
        while True:
            items, _ = self.api_service.fetch_files_in_directory_page(
                cid=target_cid, limit=self.config.API_FETCH_LIMIT, offset=offset, show_dir="1"
            )
            if not items:
                break
            for item in items:
                name = _get_item_attribute(item, "fn", "file_name")
                fid = _get_item_attribute(item, "fid", "file_id")
                if name and fid:
                    existing_target_items[name.lower()] = (fid, is_item_folder(item))
            offset += len(items)
        # === Step 2: 获取所有标记项完整信息 ===
        source_items = []
        current_page_items = self.state.get_current_display_items()
        for fid in self.state.marked_for_move_file_ids:
            found = False
            for item in current_page_items:
                if _get_item_attribute(item, "fid", "file_id") == fid:
                    source_items.append(item)
                    found = True
                    break
            if not found:
                details = self.api_service.get_item_details(fid)
                if details:
                    fake_item = {
                        "fid": fid,
                        "fn": details.get("file_name", "Unknown"),
                        "fc": "0" if details.get("file_category") == "0" else "1"
                    }
                    source_items.append(fake_item)
        if not source_items:
            logging.warning("No valid source items to process.")
            return CMD_CONTINUE_INPUT
        # === Step 3: 收集所有要移动的最终项（文件 or 文件夹的内容）===
        move_plan = []  # [(fid, final_target_cid)]
        for src_item in source_items:
            src_fid = _get_item_attribute(src_item, "fid", "file_id")
            src_name = _get_item_attribute(src_item, "fn", "file_name", default_value="Unknown")
            if not src_fid or not src_name:
                continue
            if not is_item_folder(src_item):
                # 源是文件 → 直接 move 到 target_cid
                move_plan.append((src_fid, target_cid))
                continue
            # 源是文件夹 → 获取其所有一级子项
            sub_items = []
            offset = 0
            while True:
                page, _ = self.api_service.fetch_files_in_directory_page(
                    cid=src_fid, limit=self.config.API_FETCH_LIMIT, offset=offset, show_dir="1"
                )
                if not page:
                    break
                sub_items.extend(page)
                offset += len(page)
            if not sub_items:
                logging.info(f"Source folder '{src_name}' is empty, skipped.")
                continue
            for sub_item in sub_items:
                sub_fid = _get_item_attribute(sub_item, "fid", "file_id")
                sub_name = _get_item_attribute(sub_item, "fn", "file_name")
                if not sub_fid or not sub_name:
                    continue
                if not is_item_folder(sub_item):
                    # 子项是文件 → 直接 move 到 target_cid（同名文件也尝试）
                    move_plan.append((sub_fid, target_cid))
                else:
                    # 子项是文件夹
                    sub_name_lower = sub_name.lower()
                    if sub_name_lower in existing_target_items:
                        existing_fid, existing_is_folder = existing_target_items[sub_name_lower]
                        if existing_is_folder:
                            # ✅ 目标存在同名文件夹 → 注入其内容
                            logging.info(f"Target folder '{sub_name}' already exists (FID: {existing_fid}). Injecting its contents into it.")
                            # 获取该子文件夹的所有内容（grand children）
                            grand_children = []
                            gc_offset = 0
                            while True:
                                gc_page, _ = self.api_service.fetch_files_in_directory_page(
                                    cid=sub_fid, limit=self.config.API_FETCH_LIMIT, offset=gc_offset, show_dir="1"
                                )
                                if not gc_page:
                                    break
                                grand_children.extend(gc_page)
                                gc_offset += len(gc_page)
                            for gc in grand_children:
                                gc_fid = _get_item_attribute(gc, "fid", "file_id")
                                if gc_fid:
                                    move_plan.append((gc_fid, existing_fid))
                        else:
                            # 目标是同名文件 → 仍尝试 move 到 target_cid
                            move_plan.append((sub_fid, target_cid))
                    else:
                        # 目标不存在 → 直接 move 整个子文件夹到 target_cid
                        move_plan.append((sub_fid, target_cid))
        if not move_plan:
            logging.info("No items to move after merge resolution.")
            return CMD_CONTINUE_INPUT
        # === Step 4: 按目标 CID 分组并执行 move ===
        groups: Dict[str, List[str]] = {}
        for fid, tgt_cid in move_plan:
            groups.setdefault(tgt_cid, []).append(fid)
        total_success = 0
        total_fail = 0
        MAX_MOVE = self.config.MOVE_MAX_FILE_IDS
        RATE_LIMIT = self.config.MOVE_RATE_LIMIT_FILES_PER_SECOND
        for tgt_cid, fids in groups.items():
            # 分批（不超过 MOVE_MAX_FILE_IDS）
            batches = []
            current_batch = []
            for fid in fids:
                if len(current_batch) >= MAX_MOVE:
                    batches.append(current_batch)
                    current_batch = []
                current_batch.append(fid)
            if current_batch:
                batches.append(current_batch)
            for batch in batches:
                if self.api_service.move_files(batch, tgt_cid):
                    total_success += len(batch)
                    logging.debug(f"✅ Moved {len(batch)} items to CID {tgt_cid}.")
                else:
                    total_fail += len(batch)
                    logging.warning(f"❌ Failed to move batch to CID {tgt_cid}.")
                # 速率控制
                sleep_time = len(batch) / RATE_LIMIT + 2
                time.sleep(max(sleep_time, 0))
        # === Step 5: 清理 & 日志 ===
        _log_move_operation(self.state.marked_for_move_file_ids, target_cid, self.config)
        self.state.marked_for_move_file_ids = []
        self.state._last_fetched_params_hash = None
        self.state.current_offset = 0
        if total_fail == 0:
            logging.info(f"Merge completed successfully. Total items moved: {total_success}.")
        else:
            logging.warning(f"Merge completed with {total_fail} failures.")
        return CMD_RENDER_NEEDED
    def _fetch_folder_stats_concurrent(self, folder_items: List[Tuple[str, str, Dict]]) -> List[Tuple[str, str, int]]:
        """并发获取多个文件夹的 (fid, name, total_items)（使用统一函数）"""
        fids = [fid for fid, name, _ in folder_items]
        details_map = self.api_service.get_items_details_batch(fids)
        results_out = []
        for fid, name, _ in folder_items:
            details = details_map.get(fid)
            if details:
                total = self._get_estimated_total_items(details)
                results_out.append((fid, name, total))
        return results_out
    def _command_up(self, action_choice: str, page_items: List[Dict]) -> str:
        parts = action_choice.split(' ', 1)
        if len(parts) < 2:
            logging.warning("Usage: up <index>")
            return CMD_CONTINUE_INPUT
        try:
            index = int(parts[1])
            if not (0 <= index < len(page_items)):
                logging.warning(f"Index {index} out of range.")
                return CMD_CONTINUE_INPUT
        except ValueError:
            logging.warning("Invalid index. Please enter a number.")
            return CMD_CONTINUE_INPUT
        item = page_items[index]
        file_id = _get_item_attribute(item, "fid", "file_id")
        if not file_id:
            logging.warning("Selected item has no valid ID.")
            return CMD_CONTINUE_INPUT
        details = self.api_service.get_item_details(file_id)
        if not details or not isinstance(details, dict):
            logging.error("Failed to retrieve item details via get_item_details.")
            return CMD_CONTINUE_INPUT
        paths = _get_item_attribute(details, "paths")
        if not paths or not isinstance(paths, list):
            logging.warning("No path information available for this item.")
            return CMD_CONTINUE_INPUT
        path_entries = []
        for p in paths:
            name = _get_item_attribute(p, "file_name", default_value="Unknown")
            cid = _get_item_attribute(p, "file_id", default_value="0")
            if name and cid:
                path_entries.append((name, cid))
        current_name = _get_item_attribute(item, "fn", "file_name", default_value="Current")
        if is_item_folder(item):
            path_entries.append((current_name, file_id))
        if not path_entries:
            logging.warning("No valid path entries to display.")
            return CMD_CONTINUE_INPUT
        logging.info("\n--- Path Hierarchy ---")
        for i, (name, cid) in enumerate(path_entries):
            logging.info(f"[{i}] {name} (CID: {cid})")
        logging.info("-----------------------")
        try:
            choice_input = input("Enter path index to navigate into: ").strip()
            if not choice_input:
                logging.info("No selection made.")
                return CMD_CONTINUE_INPUT
            choice_idx = int(choice_input)
            if 0 <= choice_idx < len(path_entries):
                target_name, target_cid = path_entries[choice_idx]
                self.state.parent_cid_stack.append(self.state.create_snapshot())
                self.state.current_fetch_function = self.api_service.fetch_files_in_directory_page
                self.state.current_browse_params = self.config.COMMON_BROWSE_FETCH_PARAMS.copy()
                self.state.current_browse_params["cid"] = target_cid
                self.state.current_folder_id = target_cid
                self.state.total_items = 0
                self.state.explorable_count = 0
                self.state.current_offset = 0
                self.state.showing_all_items = False
                self.state.title = f"Folder '{target_name}' List"
                self.state._last_fetched_params_hash = None
                logging.info(f"Entered directory: '{target_name}' (CID: {target_cid})")
                return CMD_RENDER_NEEDED
            else:
                logging.warning(f"Index {choice_idx} out of range.")
                return CMD_CONTINUE_INPUT
        except ValueError:
            logging.warning("Invalid input. Please enter a number.")
            return CMD_CONTINUE_INPUT
    def _command_cd(self, action_choice: str, page_items: List[Dict]) -> str:
        user_input_parts = action_choice.split()
        if len(user_input_parts) < 2:
            logging.warning("Usage: cd <index> or cd ..")
            return CMD_CONTINUE_INPUT
        target_input = user_input_parts[1]
        if target_input == '..':
            return self._command_b()
        else:
            try:
                index = int(target_input)
                current_page_items = page_items
                if 0 <= index < len(current_page_items):
                    selected_item = current_page_items[index]
                    target_cid = _get_item_attribute(selected_item, "pid", "parent_id", default_value=self.config.ROOT_CID)
                    folder_name = f"Parent of '{_get_item_attribute(selected_item, 'fn', 'file_name', default_value='Unknown File')}'"
                    action = "Entering parent directory of file"
                    if not target_cid or target_cid == 'None':
                        target_cid = self.config.ROOT_CID
                    self.state.parent_cid_stack.append(self.state.create_snapshot())
                    self.state.current_fetch_function = self.api_service.fetch_files_in_directory_page
                    self.state.current_browse_params = self.config.COMMON_BROWSE_FETCH_PARAMS.copy()
                    self.state.current_browse_params["cid"] = target_cid
                    self.state.current_folder_id = target_cid
                    self.state.total_items = 0
                    self.state.explorable_count = 0
                    self.state.current_offset = 0
                    self.state.showing_all_items = False
                    self.state.title = f"Folder '{folder_name}' List"
                    self.state._last_fetched_params_hash = None
                    logging.info(f"{action}: '{folder_name}' (CID: {target_cid}).")
                    return CMD_RENDER_NEEDED
                else:
                    logging.warning(f"Index {index} is out of current page range.")
                    return CMD_CONTINUE_INPUT
            except ValueError:
                logging.warning("Invalid index. Please provide a numeric index or '..'.")
                return CMD_CONTINUE_INPUT
    def _command_add(self, action_choice: str, page_items: List[Dict]) -> str:
        parts = action_choice.split(' ', 1)
        if len(parts) < 2:
            logging.warning("Usage: add <folder_name>.")
            return CMD_CONTINUE_INPUT
        folder_name = parts[1].strip()
        if not folder_name:
            logging.warning("Folder name cannot be empty.")
            return CMD_CONTINUE_INPUT
        parent_id = self.state.current_folder_id
        if not parent_id:
            logging.error("Could not determine current directory ID. Please ensure you are in a valid directory.")
            return CMD_CONTINUE_INPUT
        new_folder_id, new_folder_name, error_message = self.api_service.create_folder(parent_id, folder_name)
        if new_folder_id:
            logging.info(f"Folder '{new_folder_name}' (ID: {new_folder_id}) successfully created.")
            self.state._last_fetched_params_hash = None
            self.state.current_offset = 0
            return CMD_RENDER_NEEDED
        else:
            logging.error(f"Failed to create folder: {error_message}")
            return CMD_CONTINUE_INPUT
    def _command_rename(self, action_choice: str, page_items: List[Dict]) -> str:
        parts = action_choice.split(' ', 2)
        if len(parts) < 3:
            logging.warning("Usage: rename <index> <new_name>.")
            return CMD_CONTINUE_INPUT
        try:
            index = int(parts[1])
        except ValueError:
            logging.warning("Invalid index. Please enter a numeric index.")
            return CMD_CONTINUE_INPUT
        new_name = parts[2].strip()
        if not new_name:
            logging.warning("New name cannot be empty.")
            return CMD_CONTINUE_INPUT
        current_page_items = self.state.get_current_display_items()
        if not current_page_items or not (0 <= index < len(current_page_items)):
            logging.warning(f"Index {index} is out of current page range or current page has no items.")
            return CMD_CONTINUE_INPUT
        selected_item = current_page_items[index]
        file_id_to_rename = _get_item_attribute(selected_item, "fid", "file_id")
        current_file_name = _get_item_attribute(selected_item, "fn", "file_name", default_value="Unknown")
        if not file_id_to_rename:
            logging.error(f"Could not get valid ID for item '{current_file_name}' at index {index}, cannot rename.")
            return CMD_CONTINUE_INPUT
        logging.info(f"Attempting to rename '{current_file_name}' (ID: {file_id_to_rename}) to '{new_name}'.")
        success, updated_name, error_message = self.api_service.rename_file_or_folder(file_id_to_rename, new_name)
        if success:
            logging.info(f"Successfully renamed '{current_file_name}' to '{updated_name}'.")
            self.state._last_fetched_params_hash = None
            self.state.current_offset = 0
            return CMD_RENDER_NEEDED
        else:
            logging.error(f"Rename failed: {error_message}")
            return CMD_CONTINUE_INPUT
    def _command_del(self, action_choice: str, page_items_to_display: List[Dict]) -> str:
        parts = action_choice.split(' ', 1)
        if len(parts) < 2:
            logging.warning("Usage: del <index1,index2-...> or del a.")
            return CMD_CONTINUE_INPUT
        indices_str = parts[1]
        selected_indices = parse_indices_input(indices_str, len(page_items_to_display))
        if selected_indices is None or not selected_indices:
            logging.warning("Invalid delete index selection.")
            return CMD_CONTINUE_INPUT
        file_ids_to_delete = []
        file_names_to_delete = []
        for index in selected_indices:
            if 0 <= index < len(page_items_to_display):
                item = page_items_to_display[index]
                file_id = _get_item_attribute(item, "fid", "file_id")
                file_name = _get_item_attribute(item, "fn", "file_name", default_value=f"Unknown File (index: {index})")
                if file_id:
                    file_ids_to_delete.append(file_id)
                    file_names_to_delete.append(file_name)
                else:
                    logging.warning(f"Item '{file_name}' at index {index} has no valid ID, cannot delete.")
            else:
                logging.warning(f"Index {index} is out of current page range.")
        if not file_ids_to_delete:
            logging.info("No valid items to delete.")
            return CMD_CONTINUE_INPUT
        confirmation_names = ", ".join(file_names_to_delete)
        confirm = input(f"Confirm deleting the following {len(file_ids_to_delete)} file(s)/folder(s)? This operation is irreversible!\n({confirmation_names})\nPlease type 'yes' to confirm deletion: ").strip()
        if confirm.lower() == 'yes':
            logging.info(f"Deleting {len(file_ids_to_delete)} file(s)/folder(s).")
            success, error_message = self.api_service.delete_files_or_folders(file_ids_to_delete, self.state.current_folder_id)
            if success:
                logging.info("Delete operation completed successfully.")
                self.state._last_fetched_params_hash = None
                self.state.current_offset = 0
                return CMD_RENDER_NEEDED
            else:
                logging.error(f"Delete operation failed: {error_message}")
                return CMD_CONTINUE_INPUT
        else:
            logging.info("Delete operation cancelled.")
            return CMD_CONTINUE_INPUT
    def _command_upload(self) -> str:
        try:
            uploader = Uploader(self.config, self.api_service)
        except NameError:
            logging.error("错误：Uploader 类未定义。请确保 Uploader 类在当前作用域内可用。")
            return CMD_CONTINUE_INPUT
        logging.info("\n--- 开始上传本地文件/文件夹 ---")
        local_paths_to_upload = []
        print("请输入要上传的本地文件或文件夹的完整路径，每行一个。")
        print("输入一个空行表示结束输入。")
        while True:
            path_input = input("> ").strip()
            if not path_input:
                if not local_paths_to_upload:
                    logging.warning("没有输入任何路径，上传任务已取消。")
                    return CMD_CONTINUE_INPUT
                break
            if os.path.exists(path_input):
                local_paths_to_upload.append(path_input)
            else:
                logging.warning(f"路径 '{path_input}' 不存在或无法访问，请重新输入。")
        logging.info(f"已收集 {len(local_paths_to_upload)} 个路径准备上传。")
        if not hasattr(self.config, 'PREDEFINED_UPLOAD_FOLDERS'):
            logging.warning("警告: AppConfig 中未找到 'PREDEFINED_UPLOAD_FOLDERS'。将使用空的预定义列表。")
            self.config.PREDEFINED_UPLOAD_FOLDERS = {}
        target_cid = _prompt_for_folder_selection(
            current_folder_id=self.state.current_folder_id,
            predefined_folders=self.config.PREDEFINED_UPLOAD_FOLDERS,
            prompt_message="\n--- 请选择上传目标文件夹 ---"
        )
        if target_cid is None:
            logging.info("未选择目标文件夹，上传任务已取消。")
            return CMD_CONTINUE_INPUT
        logging.info(f"目标文件夹ID已确认为: {target_cid}")
        logging.info("正在开始上传，请稍候...")
        upload_results = uploader.upload_paths_to_target(local_paths_to_upload, target_cid)
        logging.info("\n--- 上传任务摘要 ---")
        successful_uploads = [res for res in upload_results if res[0]]
        failed_uploads = [res for res in upload_results if not res[0]]
        if successful_uploads:
            logging.info(f"成功: {len(successful_uploads)} 个项目")
            for _, msg in successful_uploads:
                logging.info(f"  - {msg}")
        if failed_uploads:
            logging.error(f"失败: {len(failed_uploads)} 个项目")
            for _, msg in failed_uploads:
                logging.error(f"  - {msg}")
        logging.info("--- 摘要结束 ---")
        self.state._last_fetched_params_hash = None
        return CMD_RENDER_NEEDED
    def _command_cloud(self) -> str:
        logging.info("\n--- Add Cloud Download Task ---")
        urls_input = ""
        print("Please enter download links, one per line. Enter an empty line to finish:")
        while True:
            line = input().strip()
            if not line:
                break
            urls_input += line + "\n"
        urls_input = urls_input.strip()
        if not urls_input:
            logging.warning("No links entered, cloud download task cancelled.")
            return CMD_CONTINUE_INPUT
        selected_wp_path_id = _prompt_for_folder_selection(
            self.state.current_folder_id, self.config.PREDEFINED_SAVE_FOLDERS,
            prompt_message="--- Select Download Target Folder ---"
        )
        if selected_wp_path_id is None:
            logging.info("Cloud download cancelled.")
            return CMD_CONTINUE_INPUT
        success, message, _ = self.api_service.add_cloud_download_task(urls_input, selected_wp_path_id)
        if success:
            logging.info(message)
        else:
            logging.error(message)
        return CMD_CONTINUE_INPUT
    def _fetch_directory_items(self, cid: str, current_relative_path: str):
        """返回 (items_list, [(sub_cid, sub_rel_path), ...])"""
        items_list = []
        subdirs_list = []
        offset = 0
        page_size = self.config.API_FETCH_LIMIT
        while True:
            items, total = self.api_service.fetch_files_in_directory_page(
                cid=cid, limit=page_size, offset=offset,
                **self.config.COMMON_BROWSE_FETCH_PARAMS
            )
            if not items:
                break
            for item in items:
                item_copy = item.copy()
                name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown")
                full_rel_path = join_relative_path(current_relative_path, name)
                item_copy["_relative_path"] = full_rel_path
                items_list.append(item_copy)
                if is_item_folder(item):
                    sub_cid = _get_item_attribute(item, "fid", "file_id")
                    if sub_cid:
                        subdirs_list.append((sub_cid, full_rel_path))
            offset += len(items)
            if offset >= total:
                break
        return items_list, subdirs_list
    # === 修改：并发遍历函数改为使用统一并发函数 ===
    def _concurrent_traverse_folder(self,root_cid: str, root_name: str) -> List[Dict]:
        """广度优先并发遍历目录，返回所有 item（含文件夹自身）"""
        all_items = []
        queue = deque([(root_cid, root_name)])  # (cid, relative_path)
        visited = set()
        while queue:
            batch = []
            while queue and len(batch) < self.config.API_CONCURRENT_THREADS:
                cid, rel_path = queue.popleft()
                if cid in visited:
                    continue
                visited.add(cid)
                batch.append((cid, rel_path))
            if not batch:
                break
            # 构造参数
            fetch_args_list = [{"cid": cid, "current_relative_path": rel_path} for cid, rel_path in batch]
            def wrapped_fetch(args):
                return self._fetch_directory_items(args['cid'], args['current_relative_path'])
            results = self.api_service._fetch_concurrent_pages(wrapped_fetch, fetch_args_list)
            for (cid, rel_path), res in zip(batch, results):
                if res is None:
                    logging.error(f"Error traversing CID {cid}")
                    continue
                items, subdirs = res
                all_items.extend(items)
                for sub_cid, sub_rel_path in subdirs:
                    if sub_cid not in visited:
                        queue.append((sub_cid, sub_rel_path))
        return all_items
    # ============ 优化后的 _command_c =============
    def _command_c(self, action_choice: str, page_items: List[Dict]) -> str:
        indices_str = action_choice.split(' ', 1)[1]
        selected_indices = parse_indices_input(indices_str, len(page_items))
        if not selected_indices:
            logging.warning("Invalid collection info index selection.")
            return CMD_CONTINUE_INPUT
        items_to_collect = []
        for idx in selected_indices:
            item = page_items[idx]
            items_to_collect.append(item)
        for item_info in items_to_collect:
            item_id = _get_item_attribute(item_info, "fid", "file_id")
            item_name = _get_item_attribute(item_info, "fn", "file_name", default_value="Unknown")
            if not item_id:
                logging.error(f"Item '{item_name}' has no valid ID, skipping.")
                continue
            if is_item_folder(item_info):
                logging.info(f"Starting concurrent recursive collection for folder '{item_name}' (ID: {item_id}).")
                all_collected_items = self._concurrent_traverse_folder(item_id, item_name)
            else:
                item_copy = item_info.copy()
                item_copy["_relative_path"] = item_name
                all_collected_items = [item_copy]
            # 获取详情
            if self.config.enable_concurrent_c_details_fetching:
                fids = extract_fids(all_collected_items)
                if fids:
                    details_map = self.api_service.get_items_details_batch(fids)
                    for item in all_collected_items:
                        fid = _get_item_attribute(item, "fid", "file_id")
                        if fid and fid in details_map:
                            item['_details'] = details_map[fid]
            # 保存
            safe_base_name = _get_safe_filename(item_name, self.config)
            if is_item_folder(item_info):
                output_filename = f"collected_info_{safe_base_name}.json"
            else:
                output_filename = f"collected_info_file_{safe_base_name}.json"
            json_output_dir = os.path.join(self.config.DEFAULT_TARGET_DOWNLOAD_DIR, self.config.JSON_OUTPUT_SUBDIR)
            output_filepath = os.path.join(json_output_dir, output_filename)
            save_json_output(all_collected_items, output_filepath)
            logging.info(f"Collection for '{item_name}' saved to '{output_filepath}'.")
        return CMD_CONTINUE_INPUT
    def run_browser(self) -> str:
        while True:
            self._refresh_paginator_data()
            self.state.total_display_pages = (self.state.explorable_count + self.config.PAGINATOR_DISPLAY_SIZE - 1) // self.config.PAGINATOR_DISPLAY_SIZE if self.config.PAGINATOR_DISPLAY_SIZE > 0 else 1
            self.state.current_display_page = (self.state.current_offset // self.config.PAGINATOR_DISPLAY_SIZE) + 1 if self.config.PAGINATOR_DISPLAY_SIZE > 0 else 1
            if self.state.explorable_count > 0:
                last_page_start_offset = max(0, (self.state.explorable_count - 1) // self.config.PAGINATOR_DISPLAY_SIZE * self.config.PAGINATOR_DISPLAY_SIZE)
                self.state.current_offset = min(self.state.current_offset, last_page_start_offset)
            else:
                self.state.current_offset = 0
            page_items_to_display = []
            if self.state.showing_all_items:
                page_items_to_display = self.state._all_items_cache
            else:
                start_index_in_cache = self.state.current_offset - self.state._api_cache_start_offset
                end_index_in_cache = start_index_in_cache + self.config.PAGINATOR_DISPLAY_SIZE
                page_items_to_display = self.state._api_cache_buffer[start_index_in_cache:end_index_in_cache]
                if not page_items_to_display and self.state.explorable_count > 0:
                    logging.warning(f"Warning: API returned no data or an error occurred.")
            force_full = self.state._force_full_display_next_render
            self.state._force_full_display_next_render = False
            self.ui_renderer.display_paginated_items_list(page_items_to_display, force_full_display=force_full)
            if self.state.marked_for_move_file_ids:
                logging.info(f"Marked {len(self.state.marked_for_move_file_ids)} items for move.")
            while True:
                action_choice = input(f"Page {self.state.current_display_page}/{self.state.total_display_pages}, Enter command (h for help): ").strip().lower()
                logging.info("-------------------------------")
                command_result = self.command_processor.process_command(action_choice, page_items_to_display)
                if command_result == CMD_RENDER_NEEDED:
                    break
                elif command_result == CMD_EXIT:
                    return CMD_EXIT
                elif command_result == CMD_CONTINUE_INPUT:
                    continue
                else:
                    logging.error(f"Unknown command processing result: {command_result}")
                    continue
def parse_human_readable_size(size_str: str) -> int:
    """
    将 115 API 返回的人类可读大小字符串（如 "129.91TB", "5.22GB", "0 B"）转换为字节数。
    无法解析时返回 0。
    """
    if not isinstance(size_str, str):
        return 0
    size_str = size_str.strip()
    if size_str == "0 B" or size_str == "0B" or size_str == "0":
        return 0
    # 匹配数字 + 单位（不区分大小写）
    import re
    match = re.match(r'^([\d.]+)\s*([KMGTPE]B?)?$', size_str, re.IGNORECASE)
    if not match:
        return 0
    number_str, unit = match.groups()
    try:
        number = float(number_str)
    except ValueError:
        return 0
    unit = (unit or 'B').upper().rstrip('B')
    multipliers = {
        '': 1,
        'K': 1024,
        'M': 1024 ** 2,
        'G': 1024 ** 3,
        'T': 1024 ** 4,
        'P': 1024 ** 5,
        'E': 1024 ** 6,
    }
    multiplier = multipliers.get(unit, 1)
    return int(number * multiplier)
def _get_item_attribute(item: dict, *keys: str, default_value: Any = None) -> Any:
    for key in keys:
        if key in item:
            return item[key]
    return default_value
def is_item_folder(item: dict) -> bool:
    file_category = _get_item_attribute(item, "fc", "file_category")
    return (file_category == "0")
def _get_safe_filename(original_filename: str, config: AppConfig) -> str:
    if not isinstance(original_filename, str):
        original_filename = str(original_filename)
    safe_filename = "".join(c if c.isalnum() or c in config.ALLOWED_SPECIAL_FILENAME_CHARS else '_' for c in original_filename).strip()
    safe_filename = '_'.join(filter(None, safe_filename.split('_')))
    if len(safe_filename) > config.MAX_SAFE_FILENAME_LENGTH:
        extension = os.path.splitext(safe_filename)[1]
        base_name = os.path.splitext(safe_filename)[0]
        max_base_len = config.MAX_SAFE_FILENAME_LENGTH - len(extension) - 3 if len(extension) > 0 else config.MAX_SAFE_FILENAME_LENGTH - 3
        if max_base_len > 0:
            truncated_base_name = base_name[:max_base_len] + "..."
            safe_filename = truncated_base_name + extension
        else:
            safe_filename = safe_filename[:config.MAX_SAFE_FILENAME_LENGTH]
        logging.info(f"Filename '{original_filename}' too long, truncated to '{safe_filename}'.")
    if not safe_filename:
        safe_filename = "downloaded_file_unknown"
        logging.warning(f"Filename '{original_filename}' contained invalid characters or was empty, using default name '{safe_filename}'.")
    return safe_filename
def _log_move_operation(file_ids: List[str], to_cid: str, config: AppConfig):
    log_entry = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
        "file_ids": file_ids,
        "to_cid": to_cid
    }
    log_data = []
    if os.path.exists(config.MOVE_LOG_FILE):
        try:
            with open(config.MOVE_LOG_FILE, 'r', encoding='utf-8') as f:
                log_data = json.load(f)
            if not isinstance(log_data, list):
                log_data = []
        except json.JSONDecodeError:
            logging.warning(f"Corrupted {config.MOVE_LOG_FILE} file found. Starting a new log file.")
            log_data = []
        except Exception as e:
            logging.error(f"Error reading {config.MOVE_LOG_FILE}: {e}")
            log_data = []
    log_data.append(log_entry)
    try:
        with open(config.MOVE_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=4, ensure_ascii=False)
        logging.info(f"Move operation logged to {config.MOVE_LOG_FILE}")
    except Exception as e:
        logging.error(f"Error writing to {config.MOVE_LOG_FILE}: {e}")
def format_bytes_to_human_readable(num_bytes: int) -> str:
    if num_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while num_bytes >= 1024 and i < len(size_name) - 1:
        num_bytes /= 1024
        i += 1
    s = round(num_bytes, 2)
    return f"{s} {size_name[i]}"
def format_file_item(item: Dict) -> Dict:
    file_name = _get_item_attribute(item, "fn", "file_name", default_value="N/A")
    file_size_original = _get_item_attribute(item, "fs", "file_size")
    file_id = _get_item_attribute(item, "fid", "file_id")
    pick_code = _get_item_attribute(item, "pc", "pick_code")
    item_type_raw = "Folder" if is_item_folder(item) else "File"
    size_value_str = ""
    if not is_item_folder(item):
        cached_details = item.get('_details')
        if cached_details:
            size_val_from_details = cached_details.get("size")
            if size_val_from_details is not None and isinstance(size_val_from_details, str) and size_val_from_details.strip():
                size_value_str = size_val_from_details
        elif file_size_original is not None:
            try:
                size_value_str = format_bytes_to_human_readable(int(file_size_original))
            except (ValueError, TypeError):
                size_value_str = "N/A (Original parse failed)"
    formatted_data = {
        "item_type_raw": item_type_raw,
        "name_value": str(file_name),
        "size_value": str(size_value_str),
        "id_value": str(file_id or 'N/A'),
        "pick_code_value": str(pick_code or 'N/A')
    }
    if is_item_folder(item) and item.get('_details'):
        details = item['_details']
        api_folder_size_str = _get_item_attribute(details, "size", default_value="N/A")
        formatted_data["folder_size_display"] = str(api_folder_size_str)
        raw_file_count = _get_item_attribute(details, "count", default_value=0)
        raw_folder_count = _get_item_attribute(details, "folder_count", default_value=0)
        formatted_data["file_count_display"] = str(raw_file_count)
        formatted_data["folder_count_display"] = str(raw_folder_count)
    if item.get('_details'):
        details = item['_details']
        paths = _get_item_attribute(details, "paths")
        if paths and isinstance(paths, list) and len(paths) > 0:
            full_path_segments = [_get_item_attribute(p, "file_name", default_value="") for p in paths if _get_item_attribute(p, "file_name")]
            full_path_segments.append(file_name)
            if not full_path_segments and item_type_raw == "Folder" and file_id == '0':
                formatted_data["path_display"] = "/"
            else:
                formatted_data["path_display"] = "/" + "/".join(full_path_segments)
        elif item_type_raw == "Folder" and file_id == '0':
            formatted_data["path_display"] = "/"
        else:
            formatted_data["path_display"] = "N/A (Missing path information)"
    return formatted_data
def save_json_output(data_to_save: List[Dict], filepath: str):
    if not data_to_save:
        logging.info(f"No data to save to '{filepath}'.")
        return
    output_dir = os.path.dirname(filepath)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.info(f"Created output directory: '{output_dir}'")
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({"data": data_to_save}, f, indent=4, ensure_ascii=False)
        logging.info(f"JSON file successfully written to '{filepath}'.")
    except Exception as e:
        logging.error(f"Error writing JSON file to '{filepath}': {e}")
def parse_indices_input(input_str: str, total_items: int) -> Union[List[int], None]:
    input_str_lower = input_str.lower()
    if input_str_lower == 'a' or input_str_lower == 'all':
        return list(range(total_items)) if total_items > 0 else []
    selected_indices = set()
    parts = input_str.split(',')
    for part in parts:
        part = part.strip()
        if not part: continue
        if '-' in part:
            try:
                start_str, end_str = part.split('-')
                start, end = int(start_str), int(end_str)
                if start > end:
                    logging.warning(f"Invalid range '{part}', start index greater than end index. Ignored.")
                    continue
                for i in range(start, end + 1):
                    if 0 <= i < total_items: selected_indices.add(i)
                    else: logging.warning(f"Index {i} out of valid range (0-{total_items-1}). Ignored.")
            except ValueError:
                logging.warning(f"Range '{part}' is not in the correct format. Please use 'start-end' format. Ignored.")
        else:
            try:
                index = int(part)
                if 0 <= index < total_items: selected_indices.add(index)
                else: logging.warning(f"Index {index} out of valid range (0-{total_items-1}). Ignored.")
            except ValueError:
                logging.warning(f"Index '{part}' is not in the correct format. Please enter a number or range. Ignored.")
    return sorted(list(selected_indices))
def _get_user_input(prompt_text: str, current_value: str = '', valid_values: Union[List[str], None] = None) -> str:
    while True:
        display_current_val = f" (Current: '{current_value if current_value else 'None (empty)'}')"
        user_input = input(f"{prompt_text}{display_current_val}: ").strip()
        if user_input == '':
            return current_value if current_value else ''
        if valid_values is None or user_input in valid_values:
            return user_input
        else:
            logging.warning(f"Invalid input '{user_input}'. Allowed values: {', '.join(valid_values)}. Please retry.")
def _prompt_for_folder_selection(
    current_folder_id: str,
    predefined_folders: Dict[str, int],
    prompt_message: str = "\nPlease select target folder to save to:"
) -> Union[str, None]:
    logging.info(prompt_message)
    folder_choices = {}
    folder_choices['current'] = {'name': f'Current directory ({current_folder_id})', 'id': current_folder_id}
    folder_choices['root'] = {'name': 'Root directory', 'id': '0'}
    for name, fid in predefined_folders.items():
        folder_choices[name] = {'name': name, 'id': str(fid)}
    display_options = []
    option_to_id_map = {}
    counter = 0
    display_options.append(f"[{counter}] {folder_choices['current']['name']}")
    option_to_id_map[str(counter)] = folder_choices['current']['id']
    counter += 1
    display_options.append(f"[{counter}] {folder_choices['root']['name']}")
    option_to_id_map[str(counter)] = folder_choices['root']['id']
    counter += 1
    predefined_folder_names_sorted = sorted([name for name in predefined_folders.keys()])
    for name in predefined_folder_names_sorted:
        fid = predefined_folders[name]
        display_options.append(f"[{counter}] {name}")
        option_to_id_map[str(counter)] = str(fid)
        counter += 1
    for option_str in display_options:
        print(option_str)
    print(f"[{counter}] Enter custom folder ID")
    option_to_id_map[str(counter)] = "custom"
    selected_target_id = '0'
    while True:
        choice = input(f"Enter option (0-{counter}) or directly enter CID: ").strip().lower()
        if choice == 'q':
            return None
        if choice in option_to_id_map:
            if option_to_id_map[choice] == "custom":
                custom_cid = input("Please enter custom target folder CID (or 'q' to cancel): ").strip()
                if custom_cid.lower() == 'q':
                    return None
                if custom_cid:
                    selected_target_id = custom_cid
                    break
                else:
                    logging.info("No custom CID entered, using default root directory.")
                    selected_target_id = '0'
                    break
            else:
                selected_target_id = option_to_id_map[choice]
                break
        elif choice.isdigit() and int(choice) >= 0:
            selected_target_id = choice
            break
        elif not choice:
            logging.info("No folder selected, using default root directory.")
            selected_target_id = '0'
            break
        else:
            logging.warning(f"Invalid option '{choice}', please retry.")
    return selected_target_id
def main():
    config = AppConfig()
    raw_args = sys.argv[1:]
    if not raw_args:
        # 无参数：进入交互模式（原逻辑）
        api_service_for_init = ApiService(config)
        initial_browse_params = config.PREDEFINED_FETCH_PARAMS["default_browse"]["params"].copy()
        first_api_chunk_items, total_count = api_service_for_init.fetch_files_in_directory_page(
            cid=config.ROOT_CID, limit=config.API_FETCH_LIMIT, offset=0, **initial_browse_params
        )
        if total_count == 0:
            logging.info("No files or folders found in the root directory, script terminated.")
            sys.exit(0)
        browser = FileBrowser(
            initial_cid=config.ROOT_CID,
            initial_browse_params=initial_browse_params,
            initial_api_chunk=first_api_chunk_items,
            total_items=total_count,
            config=config
        )
        exit_signal = browser.run_browser()
        if exit_signal == CMD_EXIT:
            logging.info("\n--- Script exited successfully ---")
        else:
            logging.info("\n--- Script execution completed ---")
        return
    # === 用 ';' 分割命令链 ===
    command_chain_str = ' '.join(raw_args)
    subcommand_strings = [part.strip() for part in command_chain_str.split('=') if part.strip()]
    if not subcommand_strings:
        logging.error("No valid commands after splitting by '='.")
        sys.exit(1)
    # 初始化浏览器（不进入交互）
    browser = FileBrowser(
        initial_cid=config.ROOT_CID,
        initial_browse_params=config.PREDEFINED_FETCH_PARAMS["default_browse"]["params"].copy(),
        initial_api_chunk=[],
        total_items=0,
        config=config
    )
    api_service = browser.api_service
    # 执行每个子命令
    for cmd_str in subcommand_strings:
        cmd_parts = shlex.split(cmd_str)
        if not cmd_parts:
            continue
        cmd = cmd_parts[0]
        sub_args = cmd_parts[1:]
        # === 如果命令是 'q'，立即退出 ===
        if cmd == 'q':
            logging.info("\n--- Script exited by 'q' command ---")
            return
        # === 刷新当前页数据 ===
        browser._refresh_paginator_data()
        current_page_items = browser.state.get_current_display_items()
        # === 处理纯数字命令：模拟交互模式下的索引选择 ===
        if cmd.isdigit():
            index = int(cmd)
            if not current_page_items:
                logging.error("Current page is empty, cannot select index.")
                sys.exit(1)
            if not (0 <= index < len(current_page_items)):
                logging.error(f"Index {index} out of range (0-{len(current_page_items)-1})")
                sys.exit(1)
            selected_item = current_page_items[index]
            if is_item_folder(selected_item):
                # 进入文件夹
                browser.state.parent_cid_stack.append(browser.state.create_snapshot())
                target_cid = _get_item_attribute(selected_item, "fid", "file_id", default_value=config.ROOT_CID)
                folder_name = _get_item_attribute(selected_item, "fn", "file_name", default_value="Unknown Folder")
                browser.state.current_fetch_function = api_service.fetch_files_in_directory_page
                browser.state.current_browse_params = config.PREDEFINED_FETCH_PARAMS["default_browse"]["params"].copy()
                browser.state.current_browse_params["cid"] = target_cid
                browser.state.current_folder_id = target_cid
                browser.state.total_items = 0
                browser.state.explorable_count = 0
                browser.state.current_offset = 0
                browser.state.showing_all_items = False
                browser.state.title = f"Folder '{folder_name}' List"
                browser.state._last_fetched_params_hash = None
                browser._refresh_paginator_data()
            else:
                # 是文件：加载详情
                file_id = _get_item_attribute(selected_item, "fid", "file_id")
                if file_id:
                    details = api_service.get_item_details(file_id)
                    if details:
                        cache_index = browser.state._api_cache_start_offset + index
                        if 0 <= cache_index < len(browser.state._api_cache_buffer):
                            item_copy = browser.state._api_cache_buffer[cache_index].copy()
                            item_copy['_details'] = details
                            browser.state._api_cache_buffer[cache_index] = item_copy
            continue
        # === 其他命令逻辑（保持不变）===
        # ... [此处粘贴你已有的命令处理逻辑，包括 n/p/g/s/f/cd/v/d/i/upload/cloud 等] ...
        # 注意：所有命令执行完都 continue，不退出
        # ========== 以下是原有命令执行逻辑（保持不变）==========
        if cmd == 'n':
            if not browser.state.showing_all_items:
                browser._command_n()
            continue
        elif cmd == 'p':
            if not browser.state.showing_all_items:
                browser._command_p()
            continue
        elif cmd == 'g' and len(sub_args) == 1:
            try:
                page_num = int(sub_args[0])
                browser._command_g(f"g {page_num}")
            except ValueError:
                logging.error(f"Invalid page number: {sub_args[0]}")
                sys.exit(1)
            continue
        elif cmd == 's':
            if not (3 <= len(sub_args) <= 4):
                logging.error("Usage: s <o> <asc> <type> [suffix]")
                sys.exit(1)
            o_map = {"1": "file_name", "2": "file_size", "3": "user_utime", "4": "file_type"}
            o_val = o_map.get(sub_args[0])
            asc_val = sub_args[1]
            type_val = sub_args[2]
            suffix_val = sub_args[3] if len(sub_args) == 4 else ""
            if not o_val or asc_val not in ["0", "1"] or type_val not in ["1","2","3","4","5","6","7"]:
                logging.error("Invalid 's' parameters")
                sys.exit(1)
            new_params = {
                "cid": config.ROOT_CID,
                "custom_order": "1",
                "o": o_val,
                "asc": asc_val,
                "type": type_val,
                "suffix": suffix_val
            }
            browser.state.current_browse_params = new_params
            browser.state.current_fetch_function = api_service.fetch_files_in_directory_page
            browser.state.title = f"Filtered List (o={o_val}, asc={asc_val}, type={type_val})"
            browser.state.current_offset = 0
            browser.state.showing_all_items = False
            browser.state._last_fetched_params_hash = None
            browser._refresh_paginator_data()
            continue
        elif cmd == 'f':
            if len(sub_args) != 1:
                logging.error("Usage: f <keyword>")
                sys.exit(1)
            keyword = sub_args[0]
            browser.state.current_fetch_function = api_service.search_files
            browser.state.current_browse_params = {"search_value": keyword, "cid": config.ROOT_CID}
            browser.state.title = f"Search: '{keyword}'"
            browser.state.current_offset = 0
            browser.state.showing_all_items = False
            browser.state._last_fetched_params_hash = None
            browser._refresh_paginator_data()
            continue
        elif cmd == 'cd':
            if len(sub_args) != 1:
                logging.error("Usage: cd <cid>")
                sys.exit(1)
            target_cid = sub_args[0]
            browser.state.current_fetch_function = api_service.fetch_files_in_directory_page
            browser.state.current_browse_params = config.PREDEFINED_FETCH_PARAMS["default_browse"]["params"].copy()
            browser.state.current_browse_params["cid"] = target_cid
            browser.state.current_folder_id = target_cid
            browser.state.title = f"CID: {target_cid}"
            browser.state.current_offset = 0
            browser.state.showing_all_items = False
            browser.state._last_fetched_params_hash = None
            browser._refresh_paginator_data()
            continue
        # 依赖当前页的命令
        current_page_items = browser.state.get_current_display_items()
        if not current_page_items:
            logging.error(f"Current page is empty, cannot execute '{cmd}'")
            sys.exit(1)
        def _get_indices_from_args(args_list, total):
            if not args_list:
                return []
            if args_list[0].lower() in ('a', 'all'):
                return list(range(total))
            return parse_indices_input(args_list[0], total)
        if cmd == 'v':
            indices = _get_indices_from_args(sub_args, len(current_page_items))
            if not indices:
                logging.error("No valid index for 'v'")
                sys.exit(1)
            browser._command_v(f"v {' '.join(sub_args)}", current_page_items)
            continue
        elif cmd == 'd':
            indices = _get_indices_from_args(sub_args, len(current_page_items))
            if not indices:
                logging.error("No valid index for 'd'")
                sys.exit(1)
            browser._command_d(f"d {' '.join(sub_args)}", current_page_items)
            continue
        elif cmd == 'i':
            indices = _get_indices_from_args(sub_args, len(current_page_items))
            if not indices:
                logging.error("No valid index for 'i'")
                sys.exit(1)
            browser._command_i(f"i {' '.join(sub_args)}", current_page_items)
            continue
        elif cmd == 'a':
            # 执行 "a" 命令：获取所有项目
            browser._command_a()
            # 刷新数据以确保 _all_items_cache 生效
            browser._refresh_paginator_data()
            continue
        elif cmd == 'upload':
            if len(sub_args) < 1:
                logging.error("Usage: upload <path> [target]")
                sys.exit(1)
            local_path = sub_args[0]
            if not os.path.exists(local_path):
                logging.error(f"Path not found: {local_path}")
                sys.exit(1)
            target_spec = sub_args[1] if len(sub_args) >= 2 else None
            target_cid = str(config.PREDEFINED_UPLOAD_FOLDERS.get(target_spec, '0')) if target_spec and not target_spec.isdigit() else (target_spec or '0')
            uploader = Uploader(config, api_service)
            results = uploader.upload_paths_to_target([local_path], target_cid)
            for success, msg in results:
                (logging.info if success else logging.error)(f"{'✅' if success else '❌'} {msg}")
            continue
        elif cmd == 'cloud':
            if len(sub_args) < 1:
                logging.error("Usage: cloud <urls> [target]")
                sys.exit(1)
            urls = sub_args[0]
            target_spec = sub_args[1] if len(sub_args) >= 2 else None
            target_cid = str(config.PREDEFINED_SAVE_FOLDERS.get(target_spec, '0')) if target_spec and not target_spec.isdigit() else (target_spec or '0')
            success, msg, _ = api_service.add_cloud_download_task(urls, target_cid)
            (logging.info if success else logging.error)(f"{'✅' if success else '❌'} {msg}")
            continue
        else:
            logging.error(f"Unknown command: '{cmd}'")
            sys.exit(1)
    # === 所有命令执行完毕，无条件进入交互模式（除非遇到 q）===
    logging.info("\n--- Entering interactive mode ---")
    exit_signal = browser.run_browser()
    if exit_signal == CMD_EXIT:
        logging.info("\n--- Script exited successfully ---")
    else:
        logging.info("\n--- Script execution completed ---")
if __name__ == "__main__":
    main()
