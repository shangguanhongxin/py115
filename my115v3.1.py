from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import formatdate # 新增导入
from typing import Any, Tuple, List, Dict, Union
from urllib.parse import urlencode, quote, parse_qs
import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import qrcode_terminal # Install this library: pip install qrcode-terminal
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




'''
需要rclone，mpv
全局变量中token远程路径、快捷列表必须自定义，其他变量可以自定义
全局变量中infuse需要和已安装的infuse ua一致，请自行检查是否一致,当前为mac最新版本 20250928
安卓termux下调用的是mpv-ytdl版本，如果用的是其他版本如mpv-android，mpvkt，reex，请自行修改2710行，配置文件中记得加上infuse的ua
'''

# --- Logging Configuration ---
# INFO level for high-level operations and important messages
# DEBUG level for detailed network requests and internal logic (modify this level as needed)
logging.basicConfig(level=logging.INFO, format='%(message)s')
#logging.basicConfig(level=logging.DEBUG, format='%(message)s')

# --- Command Processing Result Constants ---
CMD_RENDER_NEEDED = "render_needed"
CMD_CONTINUE_INPUT = "continue_input"
CMD_EXIT = "exit"


class AppConfig:
    """
    Encapsulates global c"onfiguration and mutable state for the application.

    Attributes:
        FILE_LIST_API_URL (str): API endpoint for listing files.
        SEARCH_API_URL (str): API endpoint for searching files.
        DOWNLOAD_API_URL (str): API endpoint for getting download URLs.
        REFERER_DOMAIN (str): Referer domain for API requests.
        GET_FOLDER_INFO_API_URL (str): API endpoint for getting folder information.
        MOVE_API_URL (str): API endpoint for moving files.
        ADD_FOLDER_API_URL (str): API endpoint for adding folders.
        UPDATE_FILE_API_URL (str): API endpoint for updating files (e.g., renaming).
        DELETE_FILE_API_URL (str): API endpoint for deleting files.
        CLOUD_DOWNLOAD_API_URL (str): API endpoint for adding cloud download tasks.
        RCLONE_TOKEN_FULL_PATH (str): Full path to the rclone token file.
        USER_AGENT (str): User-Agent string for HTTP requests.
        DEFAULT_CONNECT_TIMEOUT (int): Default connection timeout in seconds.
        DEFAULT_READ_TIMEOUT (int): Default read timeout in seconds.
        MAX_SEARCH_EXPLORE_COUNT (int): Maximum number of items to explore during a search.
        API_FETCH_LIMIT (int): Maximum number of items to fetch per API call.
        PAGINATOR_DISPLAY_SIZE (int): Number of items to display per page in the paginator.
        ROOT_CID (str): Root folder ID ('0').
        ALLOWED_SPECIAL_FILENAME_CHARS (str): Characters allowed in safe filenames.
        MAX_SAFE_FILENAME_LENGTH (int): Maximum length for safe filenames.
        DEFAULT_TARGET_DOWNLOAD_DIR (str): Default directory for downloads.
        JSON_OUTPUT_SUBDIR (str): Subdirectory for JSON output files.
        MOVE_LOG_FILE (str): Path to the move log file.
        DEFAULT_CONCURRENT_THREADS (int): Default number of concurrent threads.
        C_COMMAND_CONCURRENT_THREADS (int): Number of concurrent threads for 'c' command.
        DOWNLOAD_CONCURRENT_THREADS (int): Number of concurrent threads for downloads.
        COMMON_BROWSE_FETCH_PARAMS (dict): Common parameters for file browsing API calls.
        PREDEFINED_FETCH_PARAMS (dict): Predefined fetch parameters.
        PREDEFINED_SAVE_FOLDERS (dict): Predefined folder IDs for cloud downloads.
        DEFAULT_PLAYBACK_STRATEGY (int): Default playback strategy (1: mpv/Infuse, 2: always Infuse, Other: prompt).
        access_token (Union[str, None]): Current access token for API authentication.
        show_list_short_form (bool): Flag to show short form list (name only).
        search_more_query (bool): Flag to enable more detailed search queries.
        enable_concurrent_c_details_fetching (bool): Flag to enable concurrent fetching for 'c' command.
    """
    def __init__(self):
        # API URLs
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

        # Upload related API addresses
        self.GET_UPLOAD_TOKEN_API_URL = "https://proapi.115.com/open/upload/get_token"
        self.UPLOAD_INIT_API_URL = "https://proapi.115.com/open/upload/init"
        self.UPLOAD_RESUME_API_URL = "https://proapi.115.com/open/upload/resume"


        # 必须自定义
        # Rclone token path
        self.RCLONE_TOKEN_FULL_PATH = ""


        self.USER_AGENT = "Infuse/8.2.5361"
        self.CLIENT_ID = self._get_client_id(2)
        # Timeouts
        self.DEFAULT_CONNECT_TIMEOUT = 25
        self.DEFAULT_READ_TIMEOUT = 40

        # API Limits and Display
        self.MAX_SEARCH_EXPLORE_COUNT = 10000
        self.API_FETCH_LIMIT = 1150
        self.PAGINATOR_DISPLAY_SIZE = self._get_default_display_size()

        # Directory and File Settings
        self.ROOT_CID = '0'
        self.ALLOWED_SPECIAL_FILENAME_CHARS = "._- ()[]{}+#@&"
        self.MAX_SAFE_FILENAME_LENGTH = 150
        self.DEFAULT_TARGET_DOWNLOAD_DIR = self._get_default_download_dir()
        self.JSON_OUTPUT_SUBDIR = 'json'
        self.MOVE_LOG_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)),"move_log.json")

        # Concurrency
        self.DEFAULT_CONCURRENT_THREADS = 3
        self.C_COMMAND_CONCURRENT_THREADS = 3
        self.DOWNLOAD_CONCURRENT_THREADS = 5

        # Uoload
        # 同时上传数
        self.UPLOAD_CONCURRENT_THREADS = 1

        self.MULTIPART_UPLOAD_MIN_SIZE = 20*1024*1024    # 20MB
        self.SMALL_FILE_MAX_SIZE_FOR_5MB_CHUNKS =50*1024*1024 # 500MB
        self.CUSTOM_CHUNK_SIZE_FOR_SMALL_FILES = 24*1024*1024 #  上面两个大小之间的文件的上传切片
        self.LARGE_FILE_FIXED_CHUNK_SIZE = 50*1024*1024 # 大于50MB的文件的上传切片大小
        self.UPLOAD_RETRY_COUNT = 3  # 新增：文件上传任务的最大重试次数
        self.UPLOAD_RETRY_DELAY_SECONDS = 5 # 新增：每次重试前的等待时间（秒）
        

        # Browse Parameters (common default for file listing)
        self.COMMON_BROWSE_FETCH_PARAMS = {
            "o": "file_name",
            "asc": "1",
            "show_dir": "1",
            "custom_order": "1"
        }
        self.PREDEFINED_FETCH_PARAMS = {
            "default_browse": {
                "description": "Default browse settings (file name ascending, show folders), primarily for folder browsing",
                "params": self.COMMON_BROWSE_FETCH_PARAMS.copy()
            }
        }

        # 必须自定义，下面id只是示例，实际无效
        #Predefined Save Folders for Cloud Download
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
            '剧集-亚太': 3112729228176931828,
            '剧集-俄语': 3112729350281509084,
            '电视节目': 3112736070923860587,
            '演唱会': 3112736166268779042,
            '纪录片': 3112736229787318869,
            '其他文件': 3112736324528257038,
            'ns': 3090049925983386006
        }
        self.PREDEFINED_UPLOAD_FOLDERS =self.PREDEFINED_SAVE_FOLDERS

        # Playback Strategy
        self.DEFAULT_PLAYBACK_STRATEGY = 1 # 1: Default mpv, .iso Infuse; 2: Always Infuse; Other: Prompt

        # Mutable State (formerly global variables)
        self.access_token: Union[str, None] = None
        self.show_list_short_form: bool = True
        self.search_more_query: bool = False
        self.enable_concurrent_c_details_fetching: bool = True

    def _get_default_download_dir(self) -> str:
        """
        Determines the default download directory based on the environment.

        Returns:
            str: The default download directory path.
        """
        if "TERMUX_VERSION" in os.environ:
            return os.path.join(os.path.expanduser('~'), 'storage', 'downloads', 'aria2')
        else:
            return os.path.join(os.path.expanduser('~'), 'Downloads', 'aria2')
    def _get_default_display_size(self) -> str:
        if "TERMUX_VERSION" in os.environ:
            return 10
        else:
            return 23
    def _get_client_id(self,app):
        app_dict = {
            1: 100195135,  # "网易爆米花"
        2: 100195145,  # "fileball"
        3: 100195181,  # "infuse"
        4: 100196251,  # "myself"
        5: 100195137,  # "vidhub"
        6: 100195161,  # "senplayer"
        7: 100197303,  # "openlist"
        8: 100195313   # "clouddrive2"
    }
        return app_dict.get(app, "App name not found")
        

class TokenManager:
    """
    管理 115 网盘令牌的获取和刷新。
    提供独立函数用于直接读取、刷新和设备码认证。
    """

    def __init__(self, config: AppConfig):
        self.config = config

    def _generate_code_verifier(self, length=128):
        """
        生成 PKCE 的 code_verifier。
        """
        length = secrets.choice(range(43, 129))
        allowed_chars = string.ascii_letters + string.digits + '-._~'
        return ''.join(secrets.choice(allowed_chars) for _ in range(length))

    def _generate_code_challenge(self, code_verifier):
        """
        从 code_verifier 生成 PKCE 的 code_challenge。
        """
        sha256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(sha256).rstrip(b'=').decode('ascii')

    def _execute_shell_command(self, command: list) -> tuple[int, str, str]:
        """
        内部辅助函数：使用 subprocess 执行 shell 命令。
        仅在命令失败时记录错误。
        """
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
        """
        将格式化的令牌数据写入本地临时文件，然后使用 rclone moveto 移动到远程。
        """
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
            with open(new_token,mode='w', encoding='utf-8') as f:
                f.write(json_string_data)
            retu= subprocess.run(["rclone", "deletefile", self.config.RCLONE_TOKEN_FULL_PATH])
            command = ["rclone", "moveto",new_token , self.config.RCLONE_TOKEN_FULL_PATH]
            retu= subprocess.run(command)
        except Exception as e:
            logging.error(f"保存令牌时发生意外错误: {e}")
            return False
    
    def _get_new_tokens_via_device_code(self) -> dict | None:
        """
        执行 115 设备码认证流程以获取初始令牌。
        返回新的令牌数据字典或 None。
        """
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
                
                if status_data.get('data', {}).get('status') == 2: # 状态 2: 已授权
                    break
                time.sleep(5) # 每 5 秒轮询一次

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
            return final_token_data["data"] # 只返回 data 部分
        else:
            logging.error(f"未能获取初始令牌。响应: {final_token_data}")
            return None

    def _load_token_data_from_remote(self) -> dict | None:
        """
        从 rclone 远程文件读取令牌数据。
        返回解析后的令牌字典 (只包含 'data' 部分) 或 None。
        """
        command_cat = ["rclone", "cat", self.config.RCLONE_TOKEN_FULL_PATH]
        return_code_cat, stdout_cat, stderr_cat = self._execute_shell_command(command_cat)

        if return_code_cat == 0 and stdout_cat:
            try:
                token_container = json.loads(stdout_cat)
                if isinstance(token_container, dict) and "data" in token_container:
                    return token_container["data"] # 只返回 'data' 部分
                else:
                    logging.warning(f"警告: 远程文件 '{self.config.RCLONE_TOKEN_FULL_PATH}' 内容格式不正确（缺少 'data' 键或不是字典）。")
                    return None
            except json.JSONDecodeError:
                logging.warning(f"警告: 远程文件 '{self.config.RCLONE_TOKEN_FULL_PATH}' 内容不是有效的 JSON。")
                return None
            except Exception as e:
                logging.warning(f"警告: 解析远程令牌文件时发生未知错误: {e}。")
                return None
        else: # 其他 rclone cat 错误
            logging.warning(f"警告: 未能读取远程令牌文件 '{self.config.RCLONE_TOKEN_FULL_PATH}' (返回码: {return_code_cat}, 错误: {stderr_cat.strip()})。")
            return None
    def _refresh_access_token_from_api(self, refresh_token_value: str) -> dict | None:
        """
        使用 refresh_token 从 API 获取新的 access_token 和 refresh_token。
        返回新的令牌数据字典或 None。
        """
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
                return result["data"] # 只返回 data 部分
            else:
                logging.error(f"令牌刷新失败。错误信息: {result.get('message', '未知错误')}, 完整响应: {result}")
                return None
        except requests.exceptions.RequestException as e:
            logging.error(f"令牌刷新 API 调用失败: {e}")
            return None
        except json.JSONDecodeError:
            logging.error(f"未能解析刷新 API 响应。")
            return None


    # --- 新增的公共 API 函数 ---

    def get_access_token_from_file(self) -> dict | None:
        """
        从远程文件读取令牌数据，并直接返回其中的 access_token 和 refresh_token。
        此方法不进行任何有效性检查或刷新操作。
        返回包含 'access_token' 和 'refresh_token' 的字典，或 None。
        """
        logging.debug("尝试从远程文件直接读取令牌。")
        try:
            loaded_data = self._load_token_data_from_remote()
            
            if loaded_data and loaded_data.get("access_token"):
                logging.debug("成功从远程文件读取到令牌数据。")
                # 返回整个 data 部分，让调用者决定如何处理
                return  loaded_data.get("access_token")
            else:
                x = self.authenticate_with_device_code()
                return x
        except Exception as e:
             logging.error(f"错误：{e}")
             return None

    def refresh_and_get_new_token(self) -> dict | None:
        """
        使用提供的 refresh_token 进行令牌刷新，并返回新的令牌数据。
        如果刷新成功，新的令牌数据会保存到远程文件。
        返回包含 'access_token' 和 'refresh_token' 的字典，或 None。
        """
        loaded_data = self._load_token_data_from_remote()
        new_token_data = self._refresh_access_token_from_api(loaded_data.get("refresh_token"))
        
        if new_token_data:
            self._save_token_data_to_rclone(new_token_data, api_status_code=0) # 假设刷新成功代码为 0
            return new_token_data.get("access_token")
        else:
            logging.error("Refresh Token 刷新失败。")
            x=self.authenticate_with_device_code()
            return x

    def authenticate_with_device_code(self) -> dict | None:
        """
        执行设备码认证流程以获取新的令牌数据。
        如果认证成功，新的令牌数据会保存到远程文件。
        返回包含 'access_token' 和 'refresh_token' 的字典，或 None。
        """
        logging.info("执行新的设备码认证流程。")
        new_token_data = self._get_new_tokens_via_device_code()
        
        if new_token_data:
            logging.info("设备码认证成功，正在保存到远程文件。")
            self._save_token_data_to_rclone(new_token_data, api_status_code=0) # 假设新认证成功代码为 0
            return new_token_data.get("access_token")
        else:
            logging.error("设备码认证最终失败。")
            return None

class ApiService:
    """
    Encapsulates all direct interactions with the 115 API.
    Handles token refreshing, retries, and error management.
    """
    def __init__(self, config: AppConfig):
        """
        Initializes the ApiService with the application configuration.

        Args:
            config (AppConfig): The application configuration object.
        """
        self.config = config
        self.token=TokenManager(self.config)
        self.config.access_token=self.token.get_access_token_from_file()

    def _execute_shell_command(self, command: List[str]) -> Tuple[int, str, str]:
        """
        Executes a shell command and captures its output.

        Args:
            command (List[str]): A list of strings representing the command and its arguments.

        Returns:
            Tuple[int, str, str]: A tuple containing the return code, stdout, and stderr of the command.
        """
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
        """
        Reads the access_token from a remote JSON file using rclone cat and updates config.

        Returns:
            bool: True if the access token was successfully refreshed, False otherwise.
        """
        try:
            access_token = self.token.refresh_and_get_new_token()
            if access_token:
                self.config.access_token = access_token
                return True
        except Exception as e:
            logging.error(f"An unexpected error occurred while parsing remote token file '{self.config.RCLONE_TOKEN_FULL_PATH}': {e}")
            return False

    def _build_api_params(self, base_params: Dict, **kwargs) -> Dict:
        """
        Builds an API parameter dictionary, filtering out None values.

        Args:
            base_params (Dict): The base dictionary of parameters.
            **kwargs: Additional parameters to add or override.

        Returns:
            Dict: A new dictionary with combined and filtered parameters.
        """
        combined_params = base_params.copy()
        combined_params.update(kwargs)
        return {k: v for k, v in combined_params.items() if v is not None}

    def _call_api(self, url: str, method: str = 'GET', params: Dict = None, data: Dict = None) -> Union[Dict, None]:
        """
        Makes a single API request without retry or token refresh logic.
        Handles network errors and JSON decoding.

        Args:
            url (str): The API endpoint URL.
            method (str): The HTTP method ('GET' or 'POST').
            params (Dict, optional): Dictionary of URL parameters for GET requests. Defaults to None.
            data (Dict, optional): Dictionary of form data for POST requests. Defaults to None.

        Returns:
            Union[Dict, None]: The JSON response from the API if successful, None otherwise.
        """
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
        time.sleep(0.1)
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
            response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)

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
        """
        Performs a generic API request with token refresh and retry logic.

        Args:
            url (str): The API endpoint URL.
            method (str): The HTTP method ('GET' or 'POST').
            params (Dict, optional): Dictionary of URL parameters for GET requests. Defaults to None.
            data (Dict, optional): Dictionary of form data for POST requests. Defaults to None.
            retry_count (int): Number of times to retry the request. Defaults to 3.

        Returns:
            Union[Dict, None]: The JSON response from the API if successful, None otherwise.
        """
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
            
            time.sleep(0.1 * attempt) # Small delay for retries

            result = self._call_api(url, method, params, data)

            if result is None: # Network error, timeout, or JSON decode error from _call_api
                if attempt < retry_count - 1:
                    logging.warning(f"Attempt {attempt + 1} failed, retrying...")
                    continue
                else:
                    logging.error(f"API request to {url} failed after {retry_count} attempts due to call_api error.")
                    return None
            
            if result.get("state"): # API call succeeded
                return result
            else: # API call returned an error state
                error_message = result.get('message', 'Unknown API error')
                logging.error(f"115 API error {url}: Message: {result}.")

                if "access_token" in error_message and self._refresh_access_token():
                    logging.warning("access_token validation failed, attempting to re-read token.txt and retry...")
                    continue # Retry with new token
                elif attempt < retry_count - 1:
                    logging.warning(f"API returned error, retrying (non-token error, or refresh failed)...")
                    continue
                else:
                    logging.error(f"API request to {url} failed after {retry_count} attempts due to API error state.")
                    return result # Return the last error result if all retries fail

        logging.error(f"API request to {url} failed after {retry_count} attempts.")
        return None

    def fetch_files_in_directory_page(self, cid: str, limit: int = 10, offset: int = 0, **kwargs) -> Tuple[List[Dict], int]:
        """
        Requests API: get a list of files for a specific directory and page.

        Args:
            cid (str): The Content ID (folder ID) to fetch files from.
            limit (int): The maximum number of items to return. Defaults to 10.
            offset (int): The starting offset for pagination. Defaults to 0.
            **kwargs: Additional parameters for the file list API.

        Returns:
            Tuple[List[Dict], int]: A tuple containing a list of dictionaries representing the items
                                     on the current page, and the total count of items in the directory.
        """
        params = self._build_api_params(
            {"cid": cid, "limit": limit, "offset": offset}, 
            **kwargs
        )
        logging.debug(f"Calling fetch_files_in_directory_page with params: {params}")
        api_response = self.request(self.config.FILE_LIST_API_URL, 'GET', params)

        if api_response and isinstance(api_response.get("data"), list):
            total_count = api_response.get("count", 0)
            logging.debug(f"Successfully retrieved {len(api_response['data'])} items, offset {offset} (request limit: {limit}). Total items: {total_count}.")
            return api_response["data"], total_count
        else:
            logging.warning(f"Failed to get items for directory ID {cid}, offset {offset}, or returned empty data.")
            return [], 0

    def _fetch_all_items_general(self, fetch_function: callable, base_fetch_kwargs: Dict, total_count: int, page_size: int, thread_limit: int = 0, main_id_param_name: str = None) -> List[Dict]:
        """
        General function to fetch all items concurrently using a provided fetch_function.

        Args:
            fetch_function (callable): The function to call for fetching each page (e.g., self.fetch_files_in_directory_page, self.search_files).
            base_fetch_kwargs (Dict): Base keyword arguments for the fetch_function.
            total_count (int): The total number of items available to fetch.
            page_size (int): The number of items to fetch per page.
            thread_limit (int): The maximum number of concurrent threads to use. Defaults to 0 (uses config default).
            main_id_param_name (str, optional): The name of the primary ID parameter for the fetch_function
                                               (e.g., 'cid' for folders, 'search_value' for search).

        Returns:
            List[Dict]: A list of all fetched items.
        """
        if thread_limit == 0:
            thread_limit = self.config.DEFAULT_CONCURRENT_THREADS

        if total_count == 0:
            return []

        if not main_id_param_name or main_id_param_name not in base_fetch_kwargs:
            logging.error(f"Missing or invalid 'main_id_param_name' or it's not in 'base_fetch_kwargs' for {fetch_function.__name__}. Cannot perform bulk fetch.")
            return []

        logging.debug(f"Starting concurrent fetching of all items (Total: {total_count}, Page Size: {page_size}, Concurrent Threads: {thread_limit})")
        all_items = []
        
        main_id_value = base_fetch_kwargs.get(main_id_param_name)
        cleaned_kwargs = {k: v for k, v in base_fetch_kwargs.items() if k != main_id_param_name}

        offsets_to_fetch = []
        actual_total_to_fetch = min(total_count, self.config.MAX_SEARCH_EXPLORE_COUNT if fetch_function == self.search_files else total_count)

        for offset in range(0, actual_total_to_fetch, page_size):
            offsets_to_fetch.append(offset)

        if not offsets_to_fetch and actual_total_to_fetch > 0:
            offsets_to_fetch.append(0)

        with ThreadPoolExecutor(max_workers=thread_limit) as executor:
            futures_to_offset = {}
            for offset in offsets_to_fetch:
                page_kwargs = cleaned_kwargs.copy()
                page_kwargs['limit'] = page_size
                page_kwargs['offset'] = offset
                
                # Dynamically pass the main ID parameter using a dictionary unpacking
                futures_to_offset[executor.submit(fetch_function, **{main_id_param_name: main_id_value}, **page_kwargs)] = offset
                
            results = []
            for future in as_completed(futures_to_offset):
                offset = futures_to_offset[future]
                try:
                    page_items, _ = future.result()
                    results.append((offset, page_items))
                except Exception as exc:
                    logging.error(f"Exception occurred while fetching page at offset {offset}: {exc}")
                    results.append((offset, [])) 
            
            results.sort(key=lambda x: x[0])

            for page_offset, page_items in results:
                if page_items:
                    all_items.extend(page_items)
                    logging.debug(f"Processing results from offset {page_offset}, total items fetched so far: {len(all_items)}.")
                else:
                    logging.warning(f"Failed to get items for offset {page_offset}, or returned empty data.")

        logging.info(f"General fetching of all items completed, fetched {len(all_items)} items.")
        return all_items

    def search_files(self, search_value: str, limit: int = 10, offset: int = 0, **kwargs) -> Tuple[List[Dict], int]:
        """
        Searches for files/folders by name, fetches one page of data.

        Args:
            search_value (str): The keyword to search for.
            limit (int): The maximum number of items to return. Defaults to 10.
            offset (int): The starting offset for pagination. Defaults to 0.
            **kwargs: Additional parameters for the search API.

        Returns:
            Tuple[List[Dict], int]: A tuple containing a list of dictionaries representing the search results
                                     on the current page, and the total count of search results.
        """
        logging.debug(f"Searching for keyword: '{search_value}', fetching {limit} items from offset {offset}.")
        params = self._build_api_params(
            {"search_value": search_value, "limit": limit, "offset": offset},
            **kwargs
        )
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
        """
        Calls 115 download link API to get the download URL for a given file.

        Args:
            file_info (Dict): A dictionary containing file information (must have 'fid' and 'pc').

        Returns:
            Tuple[Union[str, None], Union[str, None], Union[str, None]]:
                - The download URL (str) if successful, None otherwise.
                - The file name (str) if successful, None otherwise.
                - An error message (str) if an error occurred, None otherwise.
        """
        def _find_download_file_data(data_payload: Union[Dict, List], file_id: str) -> Union[Dict, None]:
            """Finds the file data containing the download link in the API response payload."""
            if isinstance(data_payload, dict):
                if file_id in data_payload:
                    return data_payload.get(file_id)
                elif "url" in data_payload and data_payload.get("url", {}).get("url"):
                    return data_payload
            elif isinstance(data_payload, list) and len(data_payload) > 0:
                for item_data in data_payload:
                    if isinstance(item_data, dict) and (_get_item_attribute(item_data, "file_id", "fid") == file_id):
                        return item_data
            return None

        file_id = _get_item_attribute(file_info, "fid", "file_id")
        file_name = _get_item_attribute(file_info, "fn", "file_name", default_value="Unknown File")
        pick_code = _get_item_attribute(file_info, "pc", "pick_code")

        if is_item_folder(file_info):
            logging.info(f"Skipping folder: {file_name} (it's a directory, no direct download link).")
            return None, None, f"Skipping folder: {file_name}"
        if not all([file_id, pick_code]):
            logging.warning(f"Incomplete file information, cannot get download link. Skipping file: {file_name or file_id or 'Unknown'}")
            return None, None, f"Incomplete file information: {file_name or file_id or 'Unknown'}"

        post_data = self._build_api_params({"pick_code": pick_code})
        result = self.request(self.config.DOWNLOAD_API_URL, 'POST', data=post_data)

        if result:
            data_payload = result.get('data')
            found_file_data = _find_download_file_data(data_payload, file_id)

            if found_file_data and isinstance(found_file_data, dict) and 'url' in found_file_data:
                download_url_object = found_file_data.get('url')
                if isinstance(download_url_object, dict) and 'url' in download_url_object:
                    download_url = download_url_object.get('url')
                    if download_url:
                        logging.debug(f"Successfully retrieved download link for '{file_name}'.")
                        return download_url, file_name, None
                    else:
                        logging.warning(f"Could not parse download link for '{file_name}' (url field is empty).")
                        return None, None, f"Could not parse download link: {file_name}"
            logging.warning(f"API response 'data' field is anomalous or missing file ID '{file_id}'.")
            return None, None, f"API response format error: {file_id}"
        return None, None, f"Failed to get download link for '{file_name}'"

    def move_files(self, file_ids: List[str], to_cid: str) -> bool:
        """
        Moves files/folders to the specified target directory.

        Args:
            file_ids (List[str]): A list of file/folder IDs to move.
            to_cid (str): The Content ID (folder ID) of the target directory.

        Returns:
            bool: True if the move operation was successful, False otherwise.
        """
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
        """
        Gets file or folder details by ID.

        Args:
            file_or_folder_id (str): The ID of the file or folder.

        Returns:
            Union[Dict, None]: A dictionary containing the item details if successful, None otherwise.
        """
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

    def create_folder(self, parent_id: str, folder_name: str) -> Tuple[Union[str, None], Union[str, None], Union[str, None]]:
        """
        Creates a new folder in the specified parent directory.

        Args:
            parent_id (str): The ID of the parent directory.
            folder_name (str): The name of the new folder to create.

        Returns:
            Tuple[Union[str, None], Union[str, None], Union[str, None]]:
                - The ID of the new folder (str) if successful, None otherwise.
                - The name of the new folder (str) if successful, None otherwise.
                - An error message (str) if an error occurred, None otherwise.
        """
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
        """
        Renames a file or folder.

        Args:
            file_id (str): The ID of the file or folder to rename.
            new_file_name (str): The new name for the file or folder.

        Returns:
            Tuple[bool, Union[str, None], Union[str, None]]:
                - True if the rename operation was successful, False otherwise.
                - The updated name (str) if successful, None otherwise.
                - An error message (str) if an error occurred, None otherwise.
        """
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
        """
        Deletes files or folders in bulk.

        Args:
            file_ids (List[str]): List of file/folder IDs to delete.
            parent_id (Union[str, None]): Parent directory ID for the delete operation (optional).

        Returns:
            Tuple[bool, Union[str, None]]: (Success status, error message).
        """
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
        """
        Adds cloud download link tasks.

        Args:
            urls (str): Multiple URLs, separated by newlines.
            wp_path_id (str): Target folder ID; if not provided or '0', defaults to root.

        Returns:
            Tuple[bool, str, Union[List[Dict], None]]: (Success status, message, data list).
        """
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

            #if successful_tasks:
            #    logging.info(f"Successfully added {len(successful_tasks)} cloud download tasks.")
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
        """
        Downloads a file to the specified path.

        Args:
            url (str): The URL of the file to download.
            filename (str): The desired filename for the downloaded file.
            save_path (str): The local directory to save the file to.

        Returns:
            Tuple[bool, int, Union[str, None]]:
                - True if download was successful, False otherwise.
                - The size of the downloaded file in bytes.
                - An error message (str) if an error occurred, None otherwise.
        """
        safe_filename = _get_safe_filename(filename, self.config)
        full_path = os.path.join(save_path, safe_filename)
        os.makedirs(save_path, exist_ok=True)

        logging.info(f"Starting download of '{safe_filename}' to '{full_path}'.")
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
                logging.info(f"File '{safe_filename}' downloaded. Size: {downloaded_size / (1024*1024):.2f} MB. Time: {duration:.2f} s. Average speed: {speed:.2f} MB/s.")
                return True, downloaded_size, None
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to download file '{safe_filename}': Network or request error: {e}")
            if os.path.exists(full_path): os.remove(full_path)
            return False, 0, f"Download failed: {safe_filename} - Network error: {e}"
        except Exception as e:
            logging.error(f"An unexpected error occurred while downloading file '{safe_filename}': {e}")
            if os.path.exists(full_path): os.remove(full_path)
            return False, 0, f"Download failed: {safe_filename} - Unexpected error: {e}"


class Uploader:
    """
    Handles file upload operations to the 115 cloud drive,
    using configuration provided by an AppConfig instance and an ApiService instance.
    """
    CMD_RENDER_NEEDED = "render_needed"
    CMD_CONTINUE_INPUT = "continue_input"
    CMD_EXIT = "exit"

    _ALLOWED_SPECIAL_FILENAME_CHARS = "._- ()[]{}+#@&"
    _MAX_SAFE_FILENAME_LENGTH = 150

    def __init__(self, config: Any, api_service: Any, initial_cid: str = '0'): # Type hints updated to Any for AppConfig, ApiService
        self.config = config
        self.api_service = api_service # Store ApiService instance
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
    def _get_safe_filename(original_filename: str) -> str:
        if not isinstance(original_filename, str):
            original_filename = str(original_filename)
        safe_filename = "".join(c if c.isalnum() or c in Uploader._ALLOWED_SPECIAL_FILENAME_CHARS else '_' for c in original_filename).strip()
        safe_filename = '_'.join(filter(None, safe_filename.split('_')))
        if len(safe_filename) > Uploader._MAX_SAFE_FILENAME_LENGTH:
            extension = os.path.splitext(safe_filename)[1]
            base_name = os.path.splitext(safe_filename)[0]
            max_base_len = Uploader._MAX_SAFE_FILENAME_LENGTH - len(extension) - 3 if len(extension) > 0 else Uploader._MAX_SAFE_FILENAME_LENGTH - 3
            if max_base_len > 0:
                truncated_base_name = base_name[:max_base_len] + "..."
                safe_filename = truncated_base_name + extension
            else:
                safe_filename = safe_filename[:Uploader._MAX_SAFE_FILENAME_LENGTH]
            logging.info(f"Filename '{original_filename}' is too long, truncated to '{safe_filename}'.")
        if not safe_filename:
            safe_filename = "downloaded_file_unknown"
            logging.warning(f"Filename '{original_filename}' contains invalid characters or is empty, using default name '{safe_filename}'.")
        return safe_filename

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
        """
        计算文件的 SHA1 哈希值、前 128KB 的 SHA1 哈希值 (preid)，以及文件大小。
        """
        try:
            file_size = os.path.getsize(filepath)
            sha1_hasher = hashlib.sha1()
            pre_sha1_hasher = hashlib.sha1()
            
            # --- FIX: 使用 128KB (131072 bytes) 来计算 preid ---
            PREID_BLOCK_SIZE = 131072 
    
            with open(filepath, 'rb') as f:
                # 计算 preid (前 128KB)
                preid_data = f.read(PREID_BLOCK_SIZE)
                pre_sha1_hasher.update(preid_data)
                
                # 重置文件指针以计算完整文件的 SHA1
                f.seek(0)
                
                # 计算完整文件的 SHA1
                for chunk in iter(lambda: f.read(4096 * 1024), b''): # 使用更大的块以提高效率
                    sha1_hasher.update(chunk)
    
            return sha1_hasher.hexdigest(), pre_sha1_hasher.hexdigest(), file_size
        except Exception as e:
            logging.error(f"Error calculating file hashes for {filepath}: {e}")
            return None, None, 0
    
    def calculate_range_sha1(self, filepath: str, byte_range_str: str) -> Union[str, None]:
        """
        计算文件指定字节范围的 SHA1 哈希值，并返回大写结果。
        """
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
                # --- FIX: 确保读取长度正确 ---
                bytes_to_read = end_byte - start_byte + 1
                data = f.read(bytes_to_read)
                
                # --- FIX: 返回大写的 SHA1 值 ---
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
        """
        Calculates the OSS V1 signature for a request.

        Args:
            access_key_secret: The Access Key Secret.
            method: HTTP method (e.g., GET, PUT, POST, DELETE).
            bucket: OSS bucket name.
            object_key: OSS object key (path within the bucket).
            headers: All request headers (will be modified in-place to add 'Date' if missing).
            query_params: Dictionary of query parameters.
            content_md5: Base64 encoded MD5 of the request body (if applicable).
            content_type: Content-Type header value (if applicable).

        Returns:
            The Base64 encoded signature string.
        """
        # 1. Canonicalized Headers
        canonicalized_oss_headers = []
        # OSS headers starting with 'x-oss-' must be lowercased, sorted, and have their value trimmed.
        for k, v in sorted(headers.items()):
            k_lower = k.lower()
            if k_lower.startswith('x-oss-'):
                canonicalized_oss_headers.append(f"{k_lower}:{v.strip()}")
        canonicalized_oss_headers_str = "\n".join(canonicalized_oss_headers)

        # 2. Canonicalized Resource
        canonicalized_resource = f"/{bucket}/{object_key}"
        if query_params:
            sorted_params = sorted(query_params.items())
            param_strings = []
            for k, v in sorted_params:
                # OSS treats params without values like '?uploads' differently
                if v is not None:
                    param_strings.append(f"{k}={v}")
                else:
                    param_strings.append(f"{k}")
            canonicalized_resource += "?" + "&".join(param_strings)

        # Ensure Date header is present and in correct format
        date_header = headers.get("x-oss-date") or headers.get("date")
        if not date_header:
            date_header = formatdate(usegmt=True)
            headers["Date"] = date_header # Add to original headers for actual request

        # 3. StringToSign
        # Verb + "\n" + Content-MD5 + "\n" + Content-Type + "\n" + Date + "\n" + CanonicalizedHeaders + CanonicalizedResource
        string_to_sign = (
            f"{method}\n"
            f"{content_md5}\n"
            f"{content_type}\n"
            f"{date_header}\n" # Use the determined date_header
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
        """
        发送带签名的REST请求到OSS，增加了重试逻辑和凭证过期自动刷新功能。
        """
        # 保存原始凭证引用，以便在需要时更新
        original_credentials = oss_credentials
        
        # --- 重试逻辑开始 ---
        for attempt in range(self.config.UPLOAD_RETRY_COUNT):
            try:
                # 每次重试都需要重新获取最新的凭证值
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

                # 每次重试都需要重新生成签名
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

                # 签名必须在所有头都确定后生成
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
                    
                    # 检查是否为凭证过期错误
                    if response.status_code == 403:
                        error_text = response.text
                        if 'SecurityTokenExpired' in error_text or 'ExpiredToken' in error_text or 'InvalidAccessKeyId' in error_text:
                            logging.warning(f"OSS credentials expired or invalid (attempt {attempt + 1}). Refreshing credentials...")
                            
                            # 刷新上传凭证
                            new_oss_credentials = self.get_upload_token()
                            if new_oss_credentials:
                                # 直接更新原始凭证字典的内容
                                original_credentials.clear()
                                original_credentials.update(new_oss_credentials)
                                logging.info("OSS credentials refreshed successfully, retrying request...")
                                
                                # 等待一下再重试
                                time.sleep(2)
                                continue  # 使用新的凭证重试当前attempt
                            else:
                                logging.error("Failed to refresh OSS credentials.")
                                response.raise_for_status()
                    
                    response.raise_for_status()
                    return response  # 成功则直接返回
                    
                finally:
                    session.close()

            except requests.exceptions.HTTPError as e:
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 403:
                        error_text = e.response.text
                        if 'SecurityTokenExpired' in error_text or 'ExpiredToken' in error_text or 'InvalidAccessKeyId' in error_text:
                            logging.warning(f"OSS credentials expired or invalid (attempt {attempt + 1}). Refreshing credentials...")
                            
                            # 刷新上传凭证
                            new_oss_credentials = self.get_upload_token()
                            if new_oss_credentials:
                                # 直接更新原始凭证字典的内容
                                original_credentials.clear()
                                original_credentials.update(new_oss_credentials)
                                logging.info("OSS credentials refreshed successfully, retrying request...")
                                
                                if attempt < self.config.UPLOAD_RETRY_COUNT - 1:
                                    time.sleep(2)
                                    continue  # 使用新的凭证重试
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
        # --- 重试逻辑结束 ---


    def _oss_multipart_initiate(
        self,
        oss_credentials: Dict,
        bucket_name: str,
        object_key: str,
    ) -> str:
        """Initiates a multipart upload and returns the UploadId."""
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
                
                # Parse XML response for UploadId
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
        """Uploads a single part and returns its ETag."""
        logging.debug(f"Uploading part {part_number} for {object_key}")
        headers = {}
        query_params = {'uploadId': upload_id, 'partNumber': str(part_number)}

        # Calculate Content-MD5 for the part data
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
            raise Exception(f"Missing ETag from part {part_number} upload response for {object_key}") # Corrected object_number to object_key
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
        """Completes a multipart upload."""
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
        """Aborts a multipart upload."""
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
            # Abort returns 204 No Content on success, or 404 if not found (which is okay)
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
        """
        上传文件到阿里云OSS，支持单部分和多部分上传，包含凭证过期自动刷新功能。
        """
        logging.info(f"Starting file upload '{os.path.basename(file_path)}' to OSS via REST API...")

        if not all([oss_credentials_for_upload.get('endpoint'),
                    oss_credentials_for_upload.get('AccessKeyId'),
                    oss_credentials_for_upload.get('AccessKeySecret'),
                    oss_credentials_for_upload.get('SecurityToken')]):
            logging.error("Missing required OSS credentials (endpoint, AccessKeyId, AccessKeySecret, SecurityToken).")
            return False

        object_key = object_id.lstrip('/')

        # Base64 encode callback info for headers
        callback_base64 = self._to_base64(callback_info_json_string)
        callback_var_base64 = self._to_base64(callback_var_json_string)

        upload_success = False
        upload_id = None

        try:
            if file_size < self.config.MULTIPART_UPLOAD_MIN_SIZE:
                # --- Single-part upload ---
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
                # --- Multi-part upload ---
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
            # Abort multipart upload if it failed and an upload_id was obtained
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
        """
        Calculates the optimal part size for multipart upload based on file size.
        """
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



    def _make_api_request(self, url: str, method: str = 'GET', params: Dict = None, data: Dict = None, retry_count: int = 3) -> Union[Dict, None]:
        """
        Delegates API requests to the ApiService instance.
        """
        # _build_api_params 由 ApiService.request 内部处理，用于 'data' 和 'params'
        # retry_count 也由 ApiService.request 处理
        return self.api_service.request(
            url=url,
            method=method,
            params=params, # ApiService.request 会处理编码
            data=data,     # ApiService.request 会处理编码
        )

    def get_upload_token(self) -> Union[Dict, None]:
        """
        Gets upload credentials.
        Returns {endpoint, AccessKeySecret, SecurityToken, Expiration, AccessKeyId} or None.
        """
        logging.info("Getting upload credentials.")
        # 委托给 _make_api_request，它现在使用 self.api_service.request
        result = self._make_api_request(self.config.GET_UPLOAD_TOKEN_API_URL, 'GET')
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

        # 委托给 _make_api_request，它现在使用 self.api_service.request
        result = self._make_api_request(self.config.UPLOAD_INIT_API_URL, 'POST', data=post_data)
        print(result)#test
        return result

    def upload_resume(
        self,
        file_size: int,
        target: str,
        fileid: str,
        pick_code: str
    ) -> Union[Dict, None]:
        logging.info(f"Resuming task '{pick_code}'.")
        post_data = {
            "file_size": str(file_size),
            "target": target,
            "fileid": fileid,
            "pick_code": pick_code
        }
        # 委托给 _make_api_request，它现在使用 self.api_service.request
        result = self._make_api_request(self.config.UPLOAD_RESUME_API_URL, 'POST', data=post_data)
        return result


    def _create_folder(self, parent_cid: str, folder_name: str) -> Tuple[Union[str, None], Union[str, None], Union[str, None]]:
        """Creates a new folder in the specified parent directory."""
        post_data = {
            "pid": parent_cid,
            "cname": folder_name
        }
        # 委托给 _make_api_request，它现在使用 self.api_service.request
        response = self._make_api_request(self.config.ADD_FOLDER_API_URL, 'POST', data=post_data)
        if response and response.get('state'):
            new_folder_id = response.get('cid')
            actual_folder_name = response.get('cname')
            logging.info(f"Successfully created folder '{actual_folder_name}' with ID '{new_folder_id}' in parent '{parent_cid}'.")
            return new_folder_id, actual_folder_name, None
        else:
            error_message = response.get('message', 'Unknown error') if response else "API request failed"
            logging.error(f"Failed to create folder '{folder_name}' in '{parent_cid}': {error_message}")
            return None, None, error_message

    def _execute_single_file_upload_task(
        self,
        local_file_path: str,
        target_folder_id: str,
        topupload: int = 0
    ) -> Tuple[bool, str]:
        """
        执行单个文件的上传任务，并增加了对整个任务的重试逻辑。
        """
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
    
                    # 如果是 Status 8，直接认为是失败，并触发重试
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
    
        # 如果所有重试都失败了，函数会在这里结束
        return False, f"Upload failed for '{file_name}' after all retries."    


    def _get_upload_target_folder_id(self) -> Union[str, None]:
        logging.info("\n--- Select Upload Target Folder ---")
        folder_choices = {}

        folder_choices['current'] = {'name': f'Current Directory ({self.current_folder_id})', 'id': self.current_folder_id}
        folder_choices['root'] = {'name': 'Root Directory', 'id': '0'}

        for name, fid in self.config.PREDEFINED_UPLOAD_FOLDERS.items():
            folder_choices[name] = {'name': name, 'id': str(fid)}

        print("\nPlease select the target folder to save to:")
        display_options = []
        option_to_id_map = {}
        counter = 0

        display_options.append(f"[{counter}] {folder_choices['current']['name']}")
        option_to_id_map[str(counter)] = folder_choices['current']['id']
        counter += 1

        display_options.append(f"[{counter}] {folder_choices['root']['name']}")
        option_to_id_map[str(counter)] = folder_choices['root']['id']
        counter += 1

        predefined_folder_names_sorted = sorted([name for name in self.config.PREDEFINED_UPLOAD_FOLDERS.keys()])
        for name in predefined_folder_names_sorted:
            fid = self.config.PREDEFINED_UPLOAD_FOLDERS[name]
            display_options.append(f"[{counter}] {name}")
            option_to_id_map[str(counter)] = str(fid)
            counter += 1

        print(f"[{counter}] Enter custom folder ID")
        option_to_id_map[str(counter)] = "custom"

        selected_wp_path_id = '0'

        while True:
            choice = input(f"Enter choice ({'0'}-{counter}) or directly enter CID: ").strip().lower()
            if choice == 'q':
                return None
            if choice in option_to_id_map:
                if option_to_id_map[choice] == "custom":
                    custom_cid = input("Please enter custom target folder CID (or 'q' to cancel): ").strip()
                    if custom_cid.lower() == 'q':
                        return None
                    if custom_cid:
                        selected_wp_path_id = custom_cid
                        break
                    else:
                        logging.info("No custom CID entered, using default root directory.")
                        selected_wp_path_id = '0'
                        break
                else:
                    selected_wp_path_id = option_to_id_map[choice]
                    break
            elif choice.isdigit() and int(choice) >= 0:
                selected_wp_path_id = choice
                break
            elif not choice:
                logging.info("No folder selected, using default root directory.")
                selected_wp_path_id = '0'
                break
            else:
                logging.warning(f"Invalid choice '{choice}', please retry.")
        return selected_wp_path_id

    def upload_paths_to_target(self, local_paths: List[str], target_cid: str) -> List[Tuple[bool, str]]:
        """
        Uploads a list of local files and/or folders to a specified target folder in the cloud.
        Handles recursive folder traversal and concurrent file uploads.
        This version is optimized to fetch remote directory contents only once per directory,
        caching the results for faster batch comparisons.
    
        Args:
            local_paths (List[str]): A list of local file or folder paths to upload.
            target_cid (str): The Content ID (CID) of the target folder in the cloud.
    
        Returns:
            List[Tuple[bool, str]]: A list of tuples, each containing (success_status, message).
        """
        processing_queue = deque()
        # --- OPTIMIZATION: Cache for remote directory contents ---
        # Maps a remote CID to a dictionary of its subfolders {'folder_name': 'folder_id'}
        remote_dir_cache = {}
        files_for_concurrent_upload = []
        upload_results = []
    
        # 1. Populate initial processing queue with absolute paths
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
    
        # 2. Process the queue: create folders and collect files for upload
        while processing_queue:
            item_data = processing_queue.popleft()
            item_type = item_data['type']
            local_path = item_data['path']
            remote_parent_cid_for_item = item_data['remote_parent_cid']
    
            if item_type == 'file':
                files_for_concurrent_upload.append((local_path, remote_parent_cid_for_item))
            
            elif item_type == 'folder_creation':
                folder_name = os.path.basename(local_path)
                
                # --- MODIFICATION START: Use the cache ---
                # Check if we have already fetched the contents of the parent directory
                if remote_parent_cid_for_item not in remote_dir_cache:
                    logging.debug(f"Cache miss for CID '{remote_parent_cid_for_item}'. Fetching its contents now.")
                    
                    # Fetch all subfolders from the remote parent directory and cache them
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

                # Now, check for the folder in the cache
                existing_folder_id = remote_dir_cache[remote_parent_cid_for_item].get(folder_name)
                new_folder_id = None
                
                if existing_folder_id:
                    logging.info(f"Remote folder '{folder_name}' already exists in cache (ID: {existing_folder_id}). Will use it.")
                    new_folder_id = existing_folder_id
                else:
                    # If not in cache, create it
                    logging.info(f"Remote folder '{folder_name}' not found in cache. Creating it now.")
                    created_folder_id, _, error_msg = self.api_service.create_folder(remote_parent_cid_for_item, folder_name)
                    
                    if created_folder_id:
                        new_folder_id = created_folder_id
                        # Add the newly created folder to the cache to prevent re-creation
                        remote_dir_cache[remote_parent_cid_for_item][folder_name] = new_folder_id
                        upload_results.append((True, f"Folder '{folder_name}' created."))
                    else:
                        logging.error(f"Failed to create remote folder '{folder_name}': {error_msg}. Skipping its contents.")
                        upload_results.append((False, f"Folder creation failed: {folder_name} - {error_msg}"))
                        continue
                # --- MODIFICATION END ---
                
                # If a folder ID was found or created, process its contents
                if new_folder_id:
                    try:
                        # Add sub-files and sub-folders to the processing queue
                        for entry in os.listdir(local_path):
                            full_entry_path = os.path.join(local_path, entry)
                            if os.path.isfile(full_entry_path):
                                processing_queue.append({'type': 'file', 'path': full_entry_path, 'remote_parent_cid': new_folder_id})
                            elif os.path.isdir(full_entry_path):
                                processing_queue.append({'type': 'folder_creation', 'path': full_entry_path, 'remote_parent_cid': new_folder_id})
                    except OSError as e:
                        logging.error(f"Error listing contents of local folder '{local_path}': {e}")
                        upload_results.append((False, f"Error listing contents of folder '{local_path}': {e}"))
        
        # 3. Concurrently upload all collected files
        logging.info(f"Identified {len(files_for_concurrent_upload)} files for concurrent upload.")
    
        if files_for_concurrent_upload:
            with ThreadPoolExecutor(max_workers=self.config.UPLOAD_CONCURRENT_THREADS) as executor:
                futures = {executor.submit(self._execute_single_file_upload_task, file_path, target_cid): file_path
                           for file_path, target_cid in files_for_concurrent_upload if file_path is not None}
    
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


    def _handle_upload_command(self) -> str:
        logging.info("DEBUG: Entering _handle_upload_command. Will prompt user for input.")
        logging.info("\n--- Upload Local Files/Folders ---")
        local_paths_input = []
        print("Please enter local file or folder paths to upload, one per line. Enter an empty line to finish:")
        while True:
            line = input().strip()
            if not line:
                break
            local_paths_input.append(line)

        if not local_paths_input:
            logging.warning("No paths entered, upload task cancelled.")
            return Uploader.CMD_CONTINUE_INPUT

        selected_upload_target_id = self._get_upload_target_folder_id()
        if selected_upload_target_id is None:
            logging.info("Upload cancelled.")
            return Uploader.CMD_CONTINUE_INPUT

        # Call the new unified upload method
        upload_results = self.upload_paths_to_target(local_paths_input, selected_upload_target_id)

        logging.info("\n--- Upload Task Summary ---")
        successful_uploads = [r for r in upload_results if r[0]]
        failed_uploads = [r for r in upload_results if not r[0]]

        logging.info(f"Successful Uploads: {len(successful_uploads)} files/folders.")
        if successful_uploads:
            for _, msg in successful_uploads:
                logging.info(f"  - {msg}")

        logging.info(f"Failed Uploads: {len(failed_uploads)} files/folders.")
        if failed_uploads:
            for _, msg in failed_uploads:
                logging.error(f"  - {msg}")

        self._last_fetched_params_hash = None
        self.current_offset = 0
        self.showing_all_items = False
        return Uploader.CMD_RENDER_NEEDED




class BrowserState:
    """
    Manages all states of the browser.

    Attributes:
        config (AppConfig): The application configuration object.
        title (str): The current title of the displayed list.
        parent_cid_stack (List[Dict]): A stack to store previous browser states for navigation.
        current_browse_params (Dict): Current parameters used for browsing (e.g., current CID, sort order).
        current_fetch_function (callable): The API service function used for fetching data (e.g., fetch_files_in_directory_page, search_files).
        _last_fetched_params_hash (Union[str, None]): Hash of the parameters from the last API fetch for caching.
        _api_cache_buffer (List[Dict]): A buffer to store the last fetched API chunk.
        _api_cache_start_offset (int): The starting offset of the data in _api_cache_buffer.
        current_offset (int): The current offset in the full list of items.
        total_items (int): The total number of items available in the current view.
        explorable_count (int): The total number of items that can be explored (e.g., max for search results).
        showing_all_items (bool): Flag indicating if all items are currently being shown (no pagination).
        _all_items_cache (List[Dict]): Cache for all items when 'show all' is enabled.
        current_display_page (int): The current display page number.
        total_display_pages (int): The total number of display pages.
        _force_full_display_next_render (bool): Flag to force full detail display on the next render.
        marked_for_move_file_ids (List[str]): List of file IDs marked for a move operation.
        current_folder_id (str): The ID of the currently browsed folder.
        target_download_dir (str): The directory where files will be downloaded.
    """
    def __init__(self, initial_cid: str, initial_browse_params: Dict, initial_api_chunk: List[Dict], total_items: int, config: AppConfig):
        """
        Initializes the BrowserState.

        Args:
            initial_cid (str): The initial Content ID (folder ID) to start browsing.
            initial_browse_params (Dict): Initial browsing parameters.
            initial_api_chunk (List[Dict]): The first chunk of API data.
            total_items (int): The total number of items found for the initial view.
            config (AppConfig): The application configuration object.
        """
        self.config = config
        self.title = "Root Quick Browse List"
        self.parent_cid_stack: List[Dict] = []  # Stack to store previous states
        self.current_browse_params = initial_browse_params.copy()
        self.current_browse_params['cid'] = initial_cid
        self.current_fetch_function = None # Will be set by FileBrowser
        self._last_fetched_params_hash: Union[str, None] = None
        self._api_cache_buffer: List[Dict] = initial_api_chunk if initial_api_chunk is not None else []
        self._api_cache_start_offset = 0
        self.current_offset = 0
        self.total_items = total_items
        self.explorable_count = min(total_items, self.config.MAX_SEARCH_EXPLORE_COUNT) # Max explorable for search
        self.showing_all_items = False
        self._all_items_cache: List[Dict] = []
        self.current_display_page = 1
        self.total_display_pages = 1
        self._force_full_display_next_render = False
        self.marked_for_move_file_ids: List[str] = []
        self.current_folder_id = initial_cid
        self.target_download_dir = self.config.DEFAULT_TARGET_DOWNLOAD_DIR # Should come from AppConfig

        if initial_api_chunk is not None and len(initial_api_chunk) > 0:
            sorted_params = sorted(self.current_browse_params.items())
            self._last_fetched_params_hash = str(hash(frozenset(sorted_params)))

    def create_snapshot(self) -> Dict:
        """
        Creates a snapshot of the current browser state for the navigation stack.

        Returns:
            Dict: A dictionary representing the current state.
        """
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
        """
        Restores browser state from a given snapshot.

        Args:
            snapshot (Dict): A dictionary containing a previously saved state.
        """
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
        """
        Gets the list of items currently being displayed, either from cache or the full list.

        Returns:
            List[Dict]: A list of dictionaries representing the items for display.
        """
        if self.showing_all_items:
            return self._all_items_cache
        else:
            start_index_in_cache = self.current_offset - self._api_cache_start_offset
            end_index_in_cache = start_index_in_cache + self.config.PAGINATOR_DISPLAY_SIZE
            return self._api_cache_buffer[start_index_in_cache:end_index_in_cache]


class UIRenderer:
    """
    Responsible for all output logic to the console.
    """
    def __init__(self, config: AppConfig, state: BrowserState):
        """
        Initializes the UIRenderer with application configuration and browser state.

        Args:
            config (AppConfig): The application configuration object.
            state (BrowserState): The current browser state object.
        """
        self.config = config
        self.state = state

    def display_paginated_items_list(self, page_items_to_display: List[Dict], force_full_display: bool = False):
        """
        Encapsulates list printing logic. Implements column alignment.

        Args:
            page_items_to_display (List[Dict]): A list of item dictionaries to display on the current page.
            force_full_display (bool): If True, forces full detail display regardless of `show_list_short_form`.
        """
        logging.info(f"--- {self.state.title} Page {self.state.current_display_page}/{self.state.total_display_pages}  ---")
        if not page_items_to_display:
            logging.info("No items to display on the current page.")
            return

        processed_rows_data = []
        display_full_details = not self.config.show_list_short_form or force_full_display

        max_idx_len = 0
        max_type_content_len = 0
        max_name_value_len = 0
        max_size_display_len = 0
        max_id_display_len = 0
        max_pick_code_display_len = 0
        max_folder_size_display_len = 0
        max_file_count_display_len = 0
        max_folder_count_display_len = 0
        max_path_display_len = 0

        for i, item_raw in enumerate(page_items_to_display):
            parsed_parts = format_file_item(item_raw)
            processed_rows_data.append(parsed_parts)
            max_idx_len = max(max_idx_len, len(str(i)))
            max_type_content_len = max(max_type_content_len, len(parsed_parts["item_type_raw"]))
            max_name_value_len = max(max_name_value_len, len(parsed_parts["name_value"]))

            if display_full_details:
                max_size_display_len = max(max_size_display_len, len(parsed_parts.get("size_value", "")))
                max_id_display_len = max(max_id_display_len, len(parsed_parts.get("id_value", "")))
                max_pick_code_display_len = max(max_pick_code_display_len, len(parsed_parts.get("pick_code_value", "")))
                if is_item_folder(item_raw) and item_raw.get('_details'):
                    max_folder_size_display_len = max(max_folder_size_display_len, len(parsed_parts.get("folder_size_display", "")))
                    max_file_count_display_len = max(max_file_count_display_len, len(parsed_parts.get("file_count_display", "")))
                    max_folder_count_display_len = max(max_folder_count_display_len, len(parsed_parts.get("folder_count_display", "")))
                if item_raw.get('_details'):
                    max_path_display_len = max(max_path_display_len, len(parsed_parts.get("path_display", "")))

        for i, row_data in enumerate(processed_rows_data):
            idx_padded = str(i).rjust(max_idx_len)
            type_padded_content = row_data['item_type_raw'].ljust(max_type_content_len)
            type_column = f"[{type_padded_content}]"
            name_value_padded = row_data['name_value']

            main_line_parts = [
                f"[{idx_padded}]",
                type_column,
                f"Name: {name_value_padded}"
            ]
            logging.info(" ".join(main_line_parts))

            if display_full_details:
                indent_len = len(f"[{idx_padded}]") + 1 + len(type_column) + 1 + len("Name: ")
                indent_str = " " * indent_len
                detail_lines_to_print = []

                if row_data.get("size_value"):
                    detail_lines_to_print.append(f"Size: {row_data['size_value'].ljust(max_size_display_len)}")
                if row_data.get("id_value"):
                    detail_lines_to_print.append(f"ID: {row_data['id_value'].ljust(max_id_display_len)}")
                
                if is_item_folder(page_items_to_display[i]) and page_items_to_display[i].get('_details'):
                    if row_data.get("folder_size_display"):
                        detail_lines_to_print.append(f"Folder Size: {row_data['folder_size_display'].ljust(max_folder_size_display_len)}")
                    if row_data.get("file_count_display"):
                        detail_lines_to_print.append(f"File Count: {row_data['file_count_display'].ljust(max_file_count_display_len)}")
                    if row_data.get("folder_count_display"):
                        detail_lines_to_print.append(f"Folder Count: {row_data['folder_count_display'].ljust(max_folder_count_display_len)}")
                if  page_items_to_display[i].get('_details'):
                    if row_data.get("path_display"):
                        detail_lines_to_print.append(f"Path: {row_data['path_display'].ljust(max_path_display_len)}")

                for line in detail_lines_to_print:
                    logging.info(f"{indent_str}{line}")
        logging.info("--- List End ---")

    def display_help(self):
        """Displays available commands and their descriptions."""
        logging.info("\n--- Available Commands ---")
        commands_info = {
            'cd <index> / ..': 'Change directory. Enter specific folder index or go up to parent directory.',
            'ls': 'List current directory content (re-render current page).',
            'g <page_number>': 'Go to a specific page number.',
            'n': 'Next page.',
            'p': 'Previous page.',
            's': 'Set/adjust sorting and filtering parameters for the current list.',
            'f <keyword>': 'Search files/folders by keyword (optional advanced filters).',
            'a': 'Show all items in the current list (can be slow for large numbers of items).',
            't': 'Toggle list display mode (compact/full).',
            'd <index> / a': 'Download selected files or recursively download folders. Usage: d <index1,index2-index3,...> or d a.',
            'v <index>': 'Smart view/play selected file (provides options based on file type). Usage: v <index>.',
            'i <index> / a': 'Get detailed information for selected item(s) (file/folder). Usage: i <index1,index2-index3,...> or i a.',
            'c <index> / a': 'Recursively collect all information (raw JSON data) of specified folder and save. Usage: c <index> or c a.',
            'mc': 'Toggle concurrent detail fetching for "c" command.',
            'save <filename.json> / a <filename.json>': 'Save current page or all fetched items to a JSON file.',
            'm <index> / a': 'Mark file(s)/folder(s) for moving. Usage: m <index1,index2,...> or m a.',
            'mm': 'Move all marked file(s)/folder(s) to the current directory.',
            'add <folder_name>': 'Create a new folder in the current directory.',
            'rename <index> <new_name>': 'Rename the specified file or folder by index.',
            'del <index> / a': 'Delete selected file(s)/folder(s). Usage: del <index1,index2-...> or del a.',
            'cloud': 'Add cloud download link task (supports multiple links).',
            'upload': 'Upload local files or folders to the cloud.',
            'h': 'Display this help information.',
            'q': 'Exit the application.'
        }

        max_cmd_len = max(len(cmd) for cmd in commands_info)
        sorted_commands = sorted(commands_info.items())
        for cmd, desc in sorted_commands:
            logging.info(f"{cmd.ljust(max_cmd_len)} : {desc}")
        logging.info("--------------------------")


class CommandProcessor:
    """
    Specifically responsible for parsing and processing user input commands.
    Orchestrates calling the appropriate command handler in FileBrowser.
    """
    def __init__(self, browser_instance):
        """
        Initializes the CommandProcessor.

        Args:
            browser_instance: An instance of FileBrowser to call command handler methods on.
        """
        self.browser = browser_instance
        self.command_map = {
            'p': self.browser._command_p,
            'n': self.browser._command_n,
            'a': self.browser._command_a,
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
            'i': self.browser._command_i,
            'c': self.browser._command_c,
            'm': self.browser._command_m,
            'save': self.browser._command_save,
            'cd': self.browser._command_cd,
            'add': self.browser._command_add,
            'rename': self.browser._command_rename,
            'del': self.browser._command_del,
        }

    def process_command(self, user_input: str, page_items: List[Dict]) -> str:
        """
        Processes paginator commands based on user input.
        """
        command_parts = user_input.split(' ', 1)
        command_key = command_parts[0]

        if command_key in self.command_map:
            if command_key == 'h':
                self.command_map[command_key]()
                return CMD_CONTINUE_INPUT
            return self.command_map[command_key]()
        
        if command_key in self.prefix_command_map:
            # 确保传递正确的参数
            return self.prefix_command_map[command_key](user_input, page_items)
        
        # Default handling: index selection
        return self.browser._command_index_selection(user_input, page_items)


class FileBrowser:
    """
    Coordinates interactive file browsing, downloading, and information retrieval for 115 Netdisk.
    This class acts as an orchestrator between various modules: ApiService, BrowserState, UIRenderer,
    and CommandProcessor.
    """
    def __init__(self, initial_cid: str, initial_browse_params: Dict, initial_api_chunk: List[Dict], total_items: int, config: AppConfig):
        """
        Initializes the FileBrowser.

        Args:
            initial_cid (str): The initial Content ID (folder ID) to start browsing.
            initial_browse_params (Dict): Initial browsing parameters.
            initial_api_chunk (List[Dict]): The first chunk of API data.
            total_items (int): The total number of items found for the initial view.
            config (AppConfig): The application configuration object.
        """
        self.config = config
        self.api_service = ApiService(self.config)
        self.state = BrowserState(initial_cid, initial_browse_params, initial_api_chunk, total_items, self.config)
        self.ui_renderer = UIRenderer(self.config, self.state)
        self.command_processor = CommandProcessor(self) # Pass self to allow command processor to call command handlers

        # Set initial fetch function for state
        self.state.current_fetch_function = self.api_service.fetch_files_in_directory_page


    def _refresh_paginator_data(self) -> None:
        """
        Refreshes data and metadata in the paginator based on current paginator state and parameters.
        Checks cache before making new API requests.
        """
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
        
        # Determine the main ID parameter based on the current fetch function
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
        """
        Constructs the 'url' parameter part for Infuse x-callback-url.

        Args:
            content_url (str): The URL of the content to be played.

        Returns:
            str: The URL-encoded 'url' parameter string.
        """
        encoded_content_url = urllib.parse.quote(content_url, safe='')
        return f"url={encoded_content_url}"


    def _play_with_mpv(self, url: str, file_name:str):
        """
        使用 mpv 播放一个或多个视频。
        - 如果是单个 URL，直接播放。
        - 如果是多个 URL，在 DEFAULT_TARGET_DOWNLOAD_DIR 下创建 M3U 播放列表文件，并通过该文件播放。
        该 M3U 文件不会被自动删除。

        Args:
            urls (List[str]): 视频文件的 URL 列表。
            file_names (List[str]): 对应的文件名称列表，用于日志记录和 M3U 标题。
        """
        mpv_command_base = []
        is_termux_am_start_mode = (self.config.DEFAULT_PLAYBACK_STRATEGY == 1 and "TERMUX_VERSION" in os.environ)

        # 构建基础命令：'am start' 还是 'mpv'
        if is_termux_am_start_mode :
            # Termux 单文件特殊处理
            #如果你用mpv-ytdl
            mpv_command_base = ['am', 'start', '-n', 'is.xyz.mpv.ytdl/is.xyz.mpv.MPVActivity', '-e', 'filepath',url]

            #如果你用mpv
            #mpv_command_base = ['am', 'start', '-n', 'is.xyz.mpv/is.xyz.mpv.MPVActivity', '-e', 'filepath',url]

            #如果你用reex
            #mpv_command_base = ['am', 'start', '-n', 'xyz.re.player.ex/xyz.re.player.ex.MPVActivity',url]

        else:
            mpv_command_base = ['mpv', url,f'--user-agent={self.config.USER_AGENT}']




        subprocess.run(mpv_command_base)


    def _play_with_infuse(self, url: str, file_name: str):
        """
        Plays video using Infuse (via x-callback-url).

        Args:
            url (str): The URL of the video file.
            file_name (str): The name of the file for logging.
        """
        encoded_url_param = self._encode_url_for_infuse_param(url)
        infuse_scheme_url = f"infuse://x-callback-url/play?{encoded_url_param}"
        logging.info(f"Playing '{file_name}' with Infuse.")
        logging.debug(f"Infuse URL: {infuse_scheme_url}")
        confirm_choice = input(f"Confirm playing '{file_name}' with Infuse (current Infuse playback might be replaced)? (y/n): ").strip().lower()
        if confirm_choice == "y":
            try:
                subprocess.run(f'open {shlex.quote(infuse_scheme_url)}', shell=True, check=True)
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
        """
        Gets the download link for a single file and executes the download.

        Args:
            item (Dict): The dictionary representing the file item.
            full_target_path (str): The full local path where the file should be saved.

        Returns:
            Tuple[bool, str, Union[str, None]]:
                - True if download was successful, False otherwise.
                - The name of the downloaded file.
                - An error message (str) if an error occurred, None otherwise.
        """
        file_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown File")
        download_url, _, error_message = self.api_service.get_download_link_details(item)
        
        if download_url:
            save_dir = os.path.dirname(full_target_path)
            file_name_in_path = os.path.basename(full_target_path)
            
            success, downloaded_size, download_error_msg = self.api_service.download_file(download_url, file_name_in_path, save_dir)
            return success, file_name, download_error_msg
        else:
            return False, file_name, error_message or "Failed to get download link"

    def _execute_download_queue(self, items_with_paths_to_download: List[Tuple[Dict, str]], prefix_item_name: str = "Download"):
        """
        Executes the file download queue, supporting concurrency.

        Args:
            items_with_paths_to_download (List[Tuple[Dict, str]]): A list of tuples, each containing
                                                                    (item_dict, full_target_path).
            prefix_item_name (str): A prefix for logging messages related to this download queue.
        """
        if not items_with_paths_to_download:
            logging.info(f"{prefix_item_name}: No files to download.")
            return

        logging.info(f"{prefix_item_name}: Preparing to download {len(items_with_paths_to_download)} files using {self.config.DOWNLOAD_CONCURRENT_THREADS} concurrent threads (via thread pool).")

        with ThreadPoolExecutor(max_workers=self.config.DOWNLOAD_CONCURRENT_THREADS) as executor:
            futures = []
            for item, full_target_path in items_with_paths_to_download:
                futures.append(executor.submit(self._download_single_item_and_link, item, full_target_path))
            
            for i, future in enumerate(as_completed(futures)):
                try:
                    success, file_name, error_msg = future.result()
                    if success:
                        logging.info(f"File download completed: {file_name} (Completed {i+1}/{len(items_with_paths_to_download)})")
                    else:
                        logging.error(f"File download failed: {file_name} - {error_msg}")
                except Exception as exc:
                    logging.error(f"An unexpected exception occurred during file download: {exc}")
        logging.info(f"{prefix_item_name}: Download queue processing completed.")

    def _generic_traverse_folder_items(self, current_cid: str, item_handler_func: callable, folder_handler_func: callable = None, recursion_level: int = 0, processed_cids: set = None, **kwargs):
        """
        A generic recursive folder traversal function with support for folder structure.
        """
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
                    # 调用文件夹处理器
                    if folder_handler_func:
                        folder_handler_func(item, recursion_level, **kwargs)
                    
                    sub_cid = _get_item_attribute(item, "fid", "file_id")
                    if sub_cid and sub_cid != self.config.ROOT_CID:
                        # 更新相对路径以包含当前文件夹
                        current_relative_path = kwargs.get('current_relative_path', '')
                        folder_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown Folder")
                        new_relative_path = os.path.join(current_relative_path, folder_name)
                        
                        # 递归调用时更新相对路径
                        new_kwargs = kwargs.copy()
                        new_kwargs['current_relative_path'] = new_relative_path
                        
                        self._generic_traverse_folder_items(sub_cid, item_handler_func, folder_handler_func, recursion_level + 1, processed_cids, **new_kwargs)
                    elif not sub_cid:
                        logging.warning(f"{log_prefix}Skipping recursive collection for item with invalid CID: {item}")
                else:
                    # 调用文件处理器
                    item_handler_func(item, recursion_level, **kwargs)

            offset += page_size
        logging.debug(f"{log_prefix}Exiting generic_traverse, CID: {current_cid}.")

    def _download_item_handler(self, item: Dict, recursion_level: int, base_download_path: str, current_relative_path: str, all_items_collector: List[Tuple[Dict, str]]):
        """
        Handler for collecting download paths during traversal, preserving folder structure.

        Args:
            item (Dict): The item dictionary (file or folder).
            recursion_level (int): Current recursion depth.
            base_download_path (str): The base path for downloads.
            current_relative_path (str): The current relative path from the root download folder.
            all_items_collector (List[Tuple[Dict, str]]): List to append (item, full_target_path) to.
        """
        item_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown Item")
        
        # 构建完整的相对路径（包括当前文件的名称）
        file_relative_path = os.path.join(current_relative_path, item_name)
        full_target_path_for_file = os.path.join(base_download_path, file_relative_path)
        
        all_items_collector.append((item, full_target_path_for_file))
        logging.debug(f"{'  ' * recursion_level}Collected file for download: {file_relative_path}.")

    def _json_collection_item_handler(self, item: Dict, recursion_level: int, all_items_collector: List[Dict]):
        """
        Handler for collecting raw JSON data during traversal.

        Args:
            item (Dict): The item dictionary (file or folder).
            recursion_level (int): Current recursion depth.
            all_items_collector (List[Dict]): List to append the raw item dictionary to.
        """
        item_id = _get_item_attribute(item, "fid", "file_id")
        if item_id:
            all_items_collector.append(item)
            logging.debug(f"{'  ' * recursion_level}Collected raw JSON data for {_get_item_attribute(item, 'fn', 'file_name', default_value='Unknown Item')}.")
        else:
            logging.warning(f"{'  ' * recursion_level}Skipping JSON collection for item with invalid ID: {_get_item_attribute(item, 'fn', 'file_name', default_value='Unknown Filename')}.")

    def _download_folder_handler(self, folder: Dict, recursion_level: int, base_download_path: str, current_relative_path: str, **kwargs):
        """
        Handler for creating folder structure during download traversal.
        """
        folder_name = _get_item_attribute(folder, "fn", "file_name", default_value="Unknown Folder")
        
        # 构建文件夹的相对路径
        folder_relative_path = os.path.join(current_relative_path, folder_name)
        full_folder_path = os.path.join(base_download_path, folder_relative_path)
        
        # 确保目录存在（实际创建会在下载前统一处理）
        logging.debug(f"{'  ' * recursion_level}Will create directory: {folder_relative_path}")

    def _create_download_directories(self, files_to_download: List[Tuple[Dict, str]]):
        """
        Pre-creates all necessary directories for the download operation.
        """
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
        """
        Recursively downloads files from the specified folder and all its subfolders, preserving folder structure.

        Args:
            folder_info (Dict): Dictionary containing information about the folder to download.
            current_download_path (str): The base local path for the recursive download.
            prefix_item_name (str): A prefix for logging messages.
        """
        folder_id = _get_item_attribute(folder_info, "fid", "file_id")
        folder_name = _get_item_attribute(folder_info, "fn", "file_name", default_value="Unknown Folder")

        logging.info(f"Starting recursive file collection for folder '{folder_name}' (ID: '{folder_id}') to path: '{current_download_path}'")
        os.makedirs(current_download_path, exist_ok=True)

        all_files_to_download = []
        
        # Use the generic traverser with folder structure preservation
        # 修改后的调用方式
        self._generic_traverse_folder_items(
            current_cid=folder_id,
            item_handler_func=self._download_item_handler,
            folder_handler_func=self._download_folder_handler,
            base_download_path=current_download_path,
            current_relative_path="",  # 根文件夹的相对路径为空
            all_items_collector=all_files_to_download,
            processed_cids=set()
        )
        
        logging.info(f"File collection for folder '{folder_name}' completed, found {len(all_files_to_download)} files.")

        if all_files_to_download:
            # 首先创建所有需要的目录
            self._create_download_directories(all_files_to_download)
            
            # 然后下载文件
            self._execute_download_queue(
                all_files_to_download,
                prefix_item_name=folder_name
            )
        else:
            logging.info(f"No downloadable files found in folder '{folder_name}'.")

        logging.info(f"Recursive download for folder '{folder_name}' completed.")

    def _command_d(self, action_choice: str, page_items: List[Dict]) -> str:
        """
        Handles 'd <index> / a' (download) command: automatically determines whether it's a file download or recursive folder download.

        Args:
            action_choice (str): The full user input string (e.g., 'd 0', 'd a', 'd 1,3-5').
            page_items (List[Dict]): The list of items currently displayed on the page.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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
            logging.info(f"Starting download of {len(files_to_download_immediately)} individual files.")
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
        
        logging.info("All download tasks submitted. Please check logs for details.")
        return CMD_RENDER_NEEDED
  # --- 改造后的 _command_v 函数 ---
    def _command_v(self, action_choice: str, page_items: List[Dict]) -> str:
        """
        处理 'v' (view/play/download) 命令，支持选择多个文件。
        根据播放策略，可能将多个非 ISO 文件的直链作为播放列表传递给 mpv。

        Args:
            action_choice (str): 完整的用户输入字符串 (例如, 'v 0', 'v 0-2', 'v 0,2,4').
            page_items (List[Dict]): 当前页面显示的条目列表。

        Returns:
            str: 一个命令结果常量 (CMD_CONTINUE_INPUT)。
        """
        try:
            indices_str = action_choice.split(' ', 1)[1]
        except IndexError:
            logging.warning("Please provide item index(es) for 'v' command (e.g., 'v 0' or 'v 0,1').")
            return CMD_CONTINUE_INPUT

        selected_indices = parse_indices_input(indices_str, len(page_items))

        if not selected_indices:
            logging.warning("No valid items selected. Please provide valid index(es).")
            return CMD_CONTINUE_INPUT

        # 过滤掉文件夹和没有有效ID的项
        valid_selected_items_with_info = [] # 存储 (original_index, item_data)
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

        # --- 根据播放策略处理 ---
        if self.config.DEFAULT_PLAYBACK_STRATEGY == 1:
            # 策略 1: 默认 mpv (非ISO播放列表), ISO 用 Infuse (逐个播放)
            for original_idx, item_data in valid_selected_items_with_info:
                file_name = _get_item_attribute(item_data, "fn", "file_name", default_value="未知文件")
                logging.info(f"准备播放文件：'{file_name}'。正在获取其下载链接...")

                try:
                # --- 关键改变：在播放当前文件之前，实时获取其下载链接 ---
                # 这样确保了链接的“新鲜度”，其有效期从此刻开始计算。
                    download_url_candidate, _, _ = self.api_service.get_download_link_details(item_data)
                    
                    if download_url_candidate:

                        logging.debug(f"成功获取到 '{file_name}' 的下载链接。正在使用 Infuse 播放。")
                    # --- 播放当前文件 ---
                    # 假设 _play_with_infuse 函数会阻塞（等待播放完成）或以某种方式通知播放结束，
                    # 这样循环才能继续播放下一个文件。

                        if file_name.lower().endswith('.iso'):
                            self._play_with_infuse(download_url_candidate, file_name)
                        else:
                            self._play_with_mpv(download_url_candidate, file_name)
                except Exception as exc:
                    logging.error(f"获取 '{file_name}' 下载链接或播放时发生错误：{exc}")

            return CMD_CONTINUE_INPUT

        elif self.config.DEFAULT_PLAYBACK_STRATEGY == 2:
            # 策略 2: 总是使用 Infuse (逐个播放)
            for original_idx, item_data in valid_selected_items_with_info:
                file_name = _get_item_attribute(item_data, "fn", "file_name", default_value="未知文件")
                logging.info(f"准备播放文件：'{file_name}'。正在获取其下载链接...")

                try:
                # --- 关键改变：在播放当前文件之前，实时获取其下载链接 ---
                # 这样确保了链接的“新鲜度”，其有效期从此刻开始计算。
                    download_url_candidate, _, _ = self.api_service.get_download_link_details(item_data)

                    if download_url_candidate:
                        logging.debug(f"成功获取到 '{file_name}' 的下载链接。正在使用 Infuse 播放。")
                    # --- 播放当前文件 ---
                    # 假设 _play_with_infuse 函数会阻塞（等待播放完成）或以某种方式通知播放结束，
                    # 这样循环才能继续播放下一个文件。
                        self._play_with_infuse(download_url_candidate, file_name)

                except Exception as exc:
                    logging.error(f"获取 '{file_name}' 下载链接或播放时发生错误：{exc}")
                    
                return CMD_CONTINUE_INPUT

    def _command_i(self, action_choice: str, page_items: List[Dict]) -> str:
        """
        Handles 'i' (info/details) command, supporting concurrent detail fetching.

        Args:
            action_choice (str): The full user input string (e.g., 'i 0', 'i a', 'i 1,3-5').
            page_items (List[Dict]): The list of items currently displayed on the page.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
        indices_str = action_choice.split(' ', 1)[1]
        selected_indices = parse_indices_input(indices_str, len(page_items))

        if not selected_indices:
            logging.warning("No items selected to query for details.")
            return CMD_CONTINUE_INPUT

        items_to_fetch_details = [(idx, page_items[idx]) for idx in selected_indices if _get_item_attribute(page_items[idx], "fid", "file_id")]

        if not items_to_fetch_details:
            logging.warning("Selected items lack valid IDs, cannot fetch details.")
            return CMD_CONTINUE_INPUT

        logging.info(f"Concurrently fetching details for {len(items_to_fetch_details)} items (concurrent threads: {self.config.DEFAULT_CONCURRENT_THREADS}).")
        
        with ThreadPoolExecutor(max_workers=self.config.DEFAULT_CONCURRENT_THREADS) as executor:
            futures_to_item_index = {
                executor.submit(self.api_service.get_item_details, _get_item_attribute(item_data, "fid", "file_id")): item_index
                for item_index, item_data in items_to_fetch_details
            }

            for future in as_completed(futures_to_item_index):
                original_item_index = futures_to_item_index[future]
                try:
                    details = future.result()
                    if details:
                        page_items[original_item_index]['_details'] = details
                        logging.info(f"Successfully retrieved details for item at index {original_item_index}.")
                    else:
                        logging.warning(f"Failed to retrieve details for item at index {original_item_index}.")
                except Exception as exc:
                    logging.error(f"An exception occurred while fetching details for item at index {original_item_index}: {exc}")
        
        logging.info("Detail fetching completed for all selected items.")
        self.state._force_full_display_next_render = True
        return CMD_RENDER_NEEDED

    def _command_a(self) -> str:
        """
        Handles 'a' (get and list all) command, updates paginator state to display all items.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED).
        """
        logging.debug(f"You have chosen to retrieve all items for {self.state.title}.")
        
        total_to_fetch = self.state.explorable_count
        fetch_limit_for_all = self.config.API_FETCH_LIMIT

        # Determine the main ID parameter name based on the current fetch function
        main_param_name = 'cid' if self.state.current_fetch_function == self.api_service.fetch_files_in_directory_page else 'search_value'

        all_items_fetched = self.api_service._fetch_all_items_general(
            fetch_function=self.state.current_fetch_function,
            base_fetch_kwargs=self.state.current_browse_params,
            total_count=total_to_fetch,
            page_size=fetch_limit_for_all,
            thread_limit=self.config.DEFAULT_CONCURRENT_THREADS,
            main_id_param_name=main_param_name # Pass the determined parameter name
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
        """
        Handles 'b' command: go back to parent directory or exit if at root.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_EXIT).
        """
        if self.state.parent_cid_stack:
            prev_state = self.state.parent_cid_stack.pop()
            self.state.restore_from_snapshot(prev_state)
            logging.debug(f"Restored to parent state. Title: {self.state.title}, CID: {_get_item_attribute(self.state.current_browse_params, 'cid', default_value='N/A')}.")
            return CMD_RENDER_NEEDED
        else:
            logging.info("You are already at the root directory. Exiting script.")
            return CMD_EXIT

    def _command_g(self, action_choice: str, *args) -> str:
        """
        Handles 'g <page_number>' command.

        Args:
            action_choice (str): The full user input string (e.g., 'g 5').
            *args: Placeholder for additional arguments (not used).

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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
        """
        Handles 'p' (previous page) command.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
        if self.state.showing_all_items:
            logging.warning("Currently displaying all items, pagination not supported.")
            return CMD_CONTINUE_INPUT
        self.state.current_offset = max(0, self.state.current_offset - self.config.PAGINATOR_DISPLAY_SIZE)
        return CMD_RENDER_NEEDED

    def _command_n(self) -> str:
        """
        Handles 'n' (next page) command.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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
        """
        Handles 't' (toggle display mode) command.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED).
        """
        self.config.show_list_short_form = not self.config.show_list_short_form
        mode_text = "Compact mode (name only)" if self.config.show_list_short_form else "Full mode (all details)"
        logging.info(f"Display mode toggled to: {mode_text}.")
        return CMD_RENDER_NEEDED
    
    def _command_mc(self) -> str:
        """
        Handles 'mc' (toggle C command concurrency) command.

        Returns:
            str: A command result constant (CMD_CONTINUE_INPUT).
        """
        self.config.enable_concurrent_c_details_fetching = not self.config.enable_concurrent_c_details_fetching
        status_text = "Enabled" if self.config.enable_concurrent_c_details_fetching else "Disabled"
        logging.info(f"Concurrent detail fetching for 'c' command is now {status_text}.")
        return CMD_CONTINUE_INPUT

    def _command_f(self, action_choice: str, *args) -> str:
        """
        Handles 'f <keyword>' (file search) command.

        Args:
            action_choice (str): The full user input string (e.g., 'f movie').
            *args: Placeholder for additional arguments (not used).

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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

    def _command_s(self) -> str:
        """
        Handles 's' (set/sort/filter) command, enters file list parameter setting mode.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED).
        """
        logging.info("\n--- Adjust Browse Parameters ---")
        
        self.state.parent_cid_stack.append(self.state.create_snapshot())
        
        self.state.current_fetch_function = self.api_service.fetch_files_in_directory_page

        new_s_params = self.state.current_browse_params.copy()
        if 'cid' not in new_s_params:
            new_s_params['cid'] = self.config.ROOT_CID

        new_cid_input = _get_user_input(
            "Enter Directory ID (CID)",
            current_value=str(_get_item_attribute(new_s_params, 'cid', default_value=self.config.ROOT_CID))
        )
        new_s_params['cid'] = new_cid_input

        sort_options = {
            "1": {"o": "file_name", "label": "File Name"},
            "2": {"o": "file_size", "label": "File Size"},
            "3": {"o": "user_utime", "label": "Last Updated"},
            "4": {"o": "file_type", "label": "File Type"},
            "5": {"o": "", "label": "None (no sort)"}
        }
        print("\nSelect sort method:")
        for key, val in sort_options.items():
            print(f"[{key}] {val['label']}")
        
        current_sort_option_val = ""
        for k, v in sort_options.items():
            if _get_item_attribute(v, "o") == _get_item_attribute(new_s_params, "o"):
                current_sort_option_val = k
                break

        sort_choice = _get_user_input(
            "Enter sort option number",
            current_value=current_sort_option_val,
            valid_values=list(sort_options.keys()) + ['']
        )
        if sort_choice:
            new_s_params["o"] = _get_item_attribute(sort_options[sort_choice], "o")
            
            if _get_item_attribute(new_s_params, "o") == "":
                if "asc" in new_s_params: del new_s_params["asc"]
            else:
                asc_desc_choice = _get_user_input(
                    "Select sort direction (1: Ascending, 0: Descending)",
                    current_value=str(_get_item_attribute(new_s_params, 'asc', default_value='')),
                    valid_values=["0", "1", ""]
                )
                if asc_desc_choice:
                    new_s_params["asc"] = asc_desc_choice
                elif "asc" in new_s_params:
                    del new_s_params["asc"]
            logging.info(f"Sort method updated.")
        else:
            if "o" in new_s_params: del new_s_params["o"]
            if "asc" in new_s_params: del new_s_params["asc"]

        filter_prompts = [
            ("type", "File Type (1:documents;2:pictures;3:music;4:videos;5:compressed;6:applications;7:books)", ["1", "2", "3", "4", "5", "6", "7", ""]),
            ("suffix", "File Extension (e.g.: 'mp4', 'pdf', default: all)", None),
            ("custom_order", "Use Custom Order (0: no memory, 1: with memory, 2: folders first)", ["0", "1", "2", ""]),
            ("stdir", "Show folders when filtering files (1: show, 0: hide)", ["0", "1", ""]),
            ("star", "Filter starred files (1: yes, 0: all)", ["0", "1", ""]),
            ("cur", "Only show files in current folder (1: yes)", ["1", ""]),
            ("show_dir", "Show directories (0: no, 1: yes)", ["0", "1", ""]),
        ]

        print("\nAdjust other filter conditions:")
        for param_name, prompt_text, valid_values in filter_prompts:
            new_val_input = _get_user_input(
                prompt_text,
                current_value=str(_get_item_attribute(new_s_params, param_name, default_value='')),
                valid_values=valid_values
            )
            if new_val_input:
                new_s_params[param_name] = new_val_input
            elif param_name in new_s_params:
                del new_s_params[param_name]
        
        self.state.current_browse_params = new_s_params.copy()
        logging.debug(f"Updated browse parameters: {self.state.current_browse_params}")

        self.state.current_offset = 0
        self.state.showing_all_items = False
        self.state.title = f"Filtered list for directory '{_get_item_attribute(new_s_params, 'cid', default_value=self.config.ROOT_CID)}'"
        self.state._last_fetched_params_hash = None

        return CMD_RENDER_NEEDED

    def _command_index_selection(self, action_choice: str, page_items_to_display: List[Dict]) -> str:
        """
        Handles user input index selection (entering folder or displaying file details).

        Args:
            action_choice (str): The raw input string from the user.
            page_items_to_display (List[Dict]): The list of items currently displayed on the page.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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
            self.state.title = f"Folder '{_get_item_attribute(selected_item, 'fn', 'file_name', default_value='Unknown Folder')}' List"
            self.state._last_fetched_params_hash = None
            self.state.current_folder_id = _get_item_attribute(current_fetch_kwargs_subfolder, "cid", default_value=self.config.ROOT_CID)
            
            logging.debug(f"DEBUG: After folder selection, self.state.current_browse_params is: {self.state.current_browse_params}")
            return CMD_RENDER_NEEDED
        else:
            logging.debug(f"You selected item(s) {selected_indices}, displaying their details.")
            
            # 修复：直接显示选中项目的详细信息，而不是调用 _command_i
            self._display_selected_items_details(selected_indices, page_items_to_display)
            return CMD_CONTINUE_INPUT  # 保持当前页面，不重新渲染

    def _display_selected_items_details(self, selected_indices: List[int], page_items: List[Dict]):
        """
        Displays detailed information for selected items without using _command_i.
        
        Args:
            selected_indices (List[int]): List of selected indices.
            page_items (List[Dict]): The list of items currently displayed on the page.
        """
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
                
                # 如果有详细信息的缓存，显示更多信息
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
                    
                    # 显示路径信息
                    paths = _get_item_attribute(details, "paths")
                    if paths and isinstance(paths, list) and len(paths) > 0:
                        path_segments = [_get_item_attribute(p, "file_name", default_value="") for p in paths if _get_item_attribute(p, "file_name")]
                        full_path = "/" + "/".join(path_segments + [item_name]) if path_segments else f"/{item_name}"
                        logging.info(f"        Path: {full_path}")
                
                # 显示下载相关信息（仅文件）
                if not is_item_folder(item):
                    pick_code = _get_item_attribute(item, "pc", "pick_code", default_value="N/A")
                    logging.info(f"    Pick Code: {pick_code}")
            
            else:
                logging.warning(f"Index {index} is out of range.")
        
        logging.info("--- End of Details ---")

    def _command_h(self):
        """
        Handles 'h' (help) command by displaying available commands.
        """
        self.ui_renderer.display_help()
    
    def _command_save(self, action_choice: str) -> str:
        """
        Handles 'save' command: saves current page or all data to a JSON file.

        Args:
            action_choice (str): The full user input string (e.g., 'save my_data.json', 'save all_data.json a').

        Returns:
            str: A command result constant (CMD_CONTINUE_INPUT).
        """
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
            # Determine the main ID parameter name based on the current fetch function
            main_param_name = 'cid' if self.state.current_fetch_function == self.api_service.fetch_files_in_directory_page else 'search_value'
            items_to_save = self.api_service._fetch_all_items_general(
                fetch_function=self.state.current_fetch_function,
                base_fetch_kwargs=self.state.current_browse_params,
                total_count=self.state.explorable_count,
                page_size=self.config.API_FETCH_LIMIT,
                thread_limit=self.config.DEFAULT_CONCURRENT_THREADS,
                main_id_param_name=main_param_name # Pass the determined parameter name
            )
        else:
            items_to_save = self.state.get_current_display_items()
            logging.info("Saving current page items to JSON file.")
            
        save_json_output(items_to_save, output_filepath)
        return CMD_CONTINUE_INPUT
    
    def _command_m(self, action_choice: str, page_items: List[Dict]) -> str:
        """
        Handles 'm' command: marks file(s)/folder(s) for moving.
        Usage: m <index1,index2-index3,...> or m a.

        Args:
            action_choice (str): The full user input string.
            page_items (List[Dict]): The list of items currently displayed on the page.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
        user_input_parts = action_choice.split()
        if len(user_input_parts) < 2:
            logging.warning("Usage: m <index1,index2-index3,...> or m a.")
            return CMD_CONTINUE_INPUT
        
        indices_str = user_input_parts[1]
        current_page_items = page_items # Use the passed page_items
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
                    logging.info(f"Marked '{file_name}' (ID: {file_id}) for moving.")
                elif file_id and file_id in self.state.marked_for_move_file_ids:
                    logging.info(f"'{file_name}' (ID: {file_id}) is already in the marked list.")
            else:
                logging.warning(f"Index {index} is out of current page range.")
        
        return CMD_RENDER_NEEDED

    def _command_mm(self) -> str:
        """
        Handles 'mm' command: moves all marked files/folders to the current directory.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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
                self.state.marked_for_move_file_ids=[]
                return CMD_RENDER_NEEDED
            else:
                logging.error("Move operation failed. Please check logs.")
                return CMD_CONTINUE_INPUT
        else:
            logging.info("Move operation cancelled.")
            return CMD_CONTINUE_INPUT

    def _command_cd(self, action_choice: str, page_items: List[Dict]) -> str:
        """
        Handles 'cd' command: changes the current browsing directory.
        Usage: cd <index> or cd ..

        Args:
            action_choice (str): The full user input string.
            page_items (List[Dict]): The list of items currently displayed on the page.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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
                current_page_items = page_items # Use the passed page_items

                if 0 <= index < len(current_page_items):
                    selected_item = current_page_items[index]
                    if is_item_folder(selected_item):
                        self.state.parent_cid_stack.append(self.state.create_snapshot())

                        self.state.current_fetch_function = self.api_service.fetch_files_in_directory_page
                        new_cid = _get_item_attribute(selected_item, "fid", "file_id", default_value=self.config.ROOT_CID)
                        self.state.current_browse_params = self.config.COMMON_BROWSE_FETCH_PARAMS.copy()
                        self.state.current_browse_params["cid"] = new_cid
                        self.state.current_folder_id = new_cid
                        
                        self.state.total_items = 0
                        self.state.explorable_count = 0

                        self.state.current_offset = 0
                        self.state.showing_all_items = False
                        self.state.title = f"Folder '{_get_item_attribute(selected_item, 'fn', 'file_name', default_value='Unknown Folder')}' List"
                        self.state._last_fetched_params_hash = None
                        logging.info(f"Entering directory: '{_get_item_attribute(selected_item, 'fn', 'file_name', default_value='Unknown Folder')}'.")
                        return CMD_RENDER_NEEDED
                    else:
                        logging.warning("Selected item is not a folder, cannot enter.")
                        return CMD_CONTINUE_INPUT
                else:
                    logging.warning(f"Index {index} is out of current page range.")
                    return CMD_CONTINUE_INPUT
            except ValueError:
                logging.warning("Invalid index. Please provide a numeric index or '..'.")
                return CMD_CONTINUE_INPUT

    def _command_add(self, action_choice: str,page_items: List[Dict]) -> str:
        """
        Handles 'add <folder_name>' command: creates a new folder in the current directory.

        Args:
            action_choice (str): The full user input string.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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

    def _command_rename(self, action_choice: str,page_items: List[Dict]) -> str:
        """
        Handles 'rename <index> <new_name>' command: renames a file or folder.

        Args:
            action_choice (str): The full user input string.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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
        """
        Handles 'del <index> / a' command: deletes files or folders.

        Args:
            action_choice (str): The full user input string (e.g., 'del 0', 'del a', 'del 1,3-5').
            page_items_to_display (List[Dict]): The list of items currently displayed on the page.

        Returns:
            str: A command result constant (CMD_RENDER_NEEDED, CMD_CONTINUE_INPUT).
        """
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
        """
        处理 'upload' 命令，启动一个交互式会话来上传本地文件或文件夹。
        
        Args:
            action_choice (str): 用户输入的完整命令字符串 (此处未使用，但为保持接口一致性而保留)。
            page_items (list): 当前页面显示的项目列表 (此处未使用)。
    
        Returns:
            str: 命令处理结果常量 (CMD_RENDER_NEEDED 或 CMD_CONTINUE_INPUT)。
        """
        # 步骤 1: 实例化 Uploader
        # Uploader 需要 config 和 api_service 实例，FileBrowser 已经持有它们。
        try:
            # 假设 Uploader 类在同一个文件中定义
            uploader = Uploader(self.config, self.api_service)
        except NameError:
            logging.error("错误：Uploader 类未定义。请确保 Uploader 类在当前作用域内可用。")
            return CMD_CONTINUE_INPUT
        
        logging.info("\n--- 开始上传本地文件/文件夹 ---")
    
        # 步骤 2: 获取用户输入的多个本地路径
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
            
            # 简单验证路径是否存在
            if os.path.exists(path_input):
                local_paths_to_upload.append(path_input)
            else:
                logging.warning(f"路径 '{path_input}' 不存在或无法访问，请重新输入。")
    
        logging.info(f"已收集 {len(local_paths_to_upload)} 个路径准备上传。")
    
        # 步骤 3: 获取上传目标 ID
        # 我们将使用一个通用的辅助函数来让用户选择文件夹。
        # 您需要确保 AppConfig 中有一个 PREDEFINED_UPLOAD_FOLDERS 字典。
        # 为方便起见，您可以先将 PREDEFINED_SAVE_FOLDERS 的内容复制给它。
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
    
        # 步骤 4: 调用 Uploader 的核心上传方法
        upload_results = uploader.upload_paths_to_target(local_paths_to_upload, target_cid)
    
        # 步骤 5: 打印上传结果摘要
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
    
        # 上传后刷新当前视图，以便看到新文件
        self.state._last_fetched_params_hash = None 
        return CMD_RENDER_NEEDED
    
    
    def _command_cloud(self) -> str:
        """
        Handles 'cloud' command: adds cloud download link tasks.

        Returns:
            str: A command result constant (CMD_CONTINUE_INPUT).
        """
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
        # Corrected: Use 'is None' for comparison with None
        if selected_wp_path_id is None:
            logging.info("Cloud download cancelled.")
            return CMD_CONTINUE_INPUT

        success, message, _ = self.api_service.add_cloud_download_task(urls_input, selected_wp_path_id)
        if success:
            logging.info(message)
        else:
            logging.error(message)
        
        return CMD_CONTINUE_INPUT

    def run_browser(self) -> str:
        """
        Main paginator loop. This method drives the interactive file browser.

        Returns:
            str: A command result constant (CMD_EXIT) indicating program termination.
        """
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
                logging.info(f"Marked files/folders for move (m): {', '.join(self.state.marked_for_move_file_ids)}.")

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

    def _command_c(self, action_choice: str, page_items: List[Dict]) -> str:
        """
        Handles 'c' command: recursively collects folder information and saves to JSON.

        Args:
            action_choice (str): The full user input string (e.g., 'c 0', 'c a').
            page_items (List[Dict]): The list of items currently displayed on the page.

        Returns:
            str: A command result constant (CMD_CONTINUE_INPUT).
        """
        indices_str = action_choice.split(' ', 1)[1]
        selected_indices = parse_indices_input(indices_str, len(page_items))

        if not selected_indices:
            logging.warning("Invalid collection info index selection.")
            return CMD_CONTINUE_INPUT
        if len(selected_indices) != 1:
            logging.warning("'c' command currently supports selecting only one item for recursive info collection. Please select a valid index.")
            return CMD_CONTINUE_INPUT

        item_info = page_items[selected_indices[0]] # Get the single selected item
        if not is_item_folder(item_info):
            logging.warning("Selected item is not a folder, cannot perform recursive info collection.")
            return CMD_CONTINUE_INPUT

        folder_id = _get_item_attribute(item_info, "fid", "file_id")
        folder_name = _get_item_attribute(item_info, "fn", "file_name", default_value="Unknown Folder")

        if not folder_id:
            logging.error(f"Could not get ID for folder '{folder_name}', cannot perform recursive info collection.")
            return CMD_CONTINUE_INPUT

        logging.info(f"Starting recursive information collection for folder '{folder_name}' (ID: {folder_id}).")

        all_collected_items = []
        self._generic_traverse_folder_items(
            current_cid=folder_id,
            item_handler_func=self._json_collection_item_handler,
            all_items_collector=all_collected_items,
            processed_cids=set()# Start with an empty set for this specific traversal
        )

        if all_collected_items:
            output_filename = _get_safe_filename(f"collected_info_{folder_name}.json", self.config)
            json_output_dir = os.path.join(self.config.DEFAULT_TARGET_DOWNLOAD_DIR, self.config.JSON_OUTPUT_SUBDIR)
            output_filepath = os.path.join(json_output_dir, output_filename)
            save_json_output(all_collected_items, output_filepath)
            logging.info(f"All information for folder '{folder_name}' collected and saved to '{output_filepath}'.")
        else:
            logging.info(f"No collectable information found in folder '{folder_name}'.")
        
        return CMD_CONTINUE_INPUT


# --- Helper Functions: General utility functions not dependent on FileBrowser instance state ---
# These functions now receive a config object to access configuration and constants
def _get_item_attribute(item: dict, *keys: str, default_value: Any = None) -> Any:
    """
    Attempts to get the value of the first existing key from a dictionary.
    If none of the provided keys exist, returns the default_value.

    Args:
        item (dict): The dictionary to search within.
        *keys (str): Variable number of string keys to try in order.
        default_value (Any, optional): The value to return if no key is found. Defaults to None.

    Returns:
        Any: The value associated with the first found key, or default_value.
    """
    for key in keys:
        if key in item:
            return item[key]
    return default_value

def is_item_folder(item: dict) -> bool:
    """
    Checks if a dictionary item represents a folder based on its 'fc' or 'file_category' attribute.

    Args:
        item (dict): The dictionary representing an item.

    Returns:
        bool: True if the item is a folder, False otherwise.
    """
    file_category = _get_item_attribute(item, "fc", "file_category")
    return (file_category == "0")

def _get_safe_filename(original_filename: str, config: AppConfig) -> str:
    """
    Cleans a filename by removing illegal characters, replacing with underscores,
    and truncating to a safe length.

    Args:
        original_filename (str): The original filename string.
        config (AppConfig): The application configuration object.

    Returns:
        str: A cleaned and safe filename string.
    """
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
    """
    Logs successful move operations to a JSON file.

    Args:
        file_ids (List[str]): A list of IDs of the files/folders that were moved.
        to_cid (str): The destination CID (folder ID) where items were moved.
        config (AppConfig): The application configuration object.
    """
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
    """
    Converts bytes to a human-readable format (B, KB, MB, GB, TB).

    Args:
        num_bytes (int): The number of bytes.

    Returns:
        str: A string representing the size in a human-readable format.
    """
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
    """
    Deconstructs single file or directory item info into components for aligned display.

    Args:
        item (Dict): The raw dictionary representing a file or folder item.

    Returns:
        Dict: A formatted dictionary with display-ready values.
    """
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
    if  item.get('_details'):
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
    """
    Saves data to a JSON file.

    Args:
        data_to_save (List[Dict]): The list of dictionaries to save.
        filepath (str): The full path to the output JSON file.
    """
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
    """
    Parses user-entered indices, supporting single indices, comma-separated lists, and ranges (e.g., '0', '1,3,5', '2-4', 'a').

    Args:
        input_str (str): The raw input string from the user.
        total_items (int): The total number of available items (for validation).

    Returns:
        Union[List[int], None]: A sorted list of unique integer indices, or None if input is invalid.
    """
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
    """
    Generic function to get user input with an optional current value and validation.

    Args:
        prompt_text (str): The text to display as a prompt to the user.
        current_value (str): The current default value to show to the user. Defaults to ''.
        valid_values (Union[List[str], None]): An optional list of valid string inputs. If None, any input is valid.

    Returns:
        str: The validated user input.
    """
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
    """
    Helper function to prompt user for folder selection.
    Can be used for download and upload targets.

    Args:
        current_folder_id (str): The ID of the currently active folder.
        predefined_folders (Dict[str, int]): A dictionary of predefined folder names and their CIDs.
        prompt_message (str): The message to display before showing folder options.

    Returns:
        Union[str, None]: The selected folder ID (str) or None if cancelled.
    """
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
    """Main function: entry point of the program."""
    config = AppConfig()
    
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


if __name__ == "__main__":
    main()

