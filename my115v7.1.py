from __future__ import annotations
from collections import defaultdict
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import formatdate
from typing import Any, Tuple, List, Dict, Union, Callable
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

logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)

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
# === 新增：通用辅助函数 ===
def extract_fids(items: List[Dict]) -> List[str]:
    """从 item 列表中提取 fid 列表"""
    return [_get_item_attribute(item, "fid", "file_id") for item in items if _get_item_attribute(item, "fid", "file_id")]
def join_relative_path(base: str, name: str) -> str:
    """安全地拼接相对路径"""
    return os.path.join(base, name).replace("\\", "/")
def get_predefined_folder_list(predefined: Dict[str, int]) -> List[Tuple[str, str]]:
    """返回 [(name, str(cid)), ...] 列表，保持固定顺序（按键名排序）"""
    return [(name, str(cid)) for name, cid in sorted(predefined.items())]
def is_item_folder(item: dict) -> bool:
    file_category = _get_item_attribute(item, "fc", "file_category")
    return (file_category == "0")
def _get_item_attribute(item: dict, *keys: str, default_value: Any = None) -> Any:
    for key in keys:
        if key in item:
            return item[key]
    return default_value
def enrich_items_with_details(items: List[Dict], api_service: 'ApiService') -> None:
    """为 items 列表中的每个 item 添加 '_details' 字段（如果能获取到）"""
    fids = extract_fids(items)
    if not fids:
        return
    details_map = api_service.get_items_details_batch(fids)
    for item in items:
        fid = _get_item_attribute(item, "fid", "file_id")
        if fid and fid in details_map:
            item['_details'] = details_map[fid]
def resolve_target_cid(target_spec: str, predefined: Dict[str, int]) -> str:
    """解析目标 CID，支持预设名称和数字 CID"""
    if not target_spec:
        return '0'
    if target_spec.isdigit():
        return target_spec
    return str(predefined.get(target_spec, '0'))
# ====================== Uploader 类（从 my115.txt 完整移植并修正）======================
class Uploader:
    CMD_RENDER_NEEDED = "render_needed"
    CMD_CONTINUE_INPUT = "continue_input"
    CMD_EXIT = "exit"
    def __init__(self, config: 'AppConfig', api_service: 'ApiService', initial_cid: str = '0'):
        self.config = config
        self.api_service = api_service
        self.current_folder_id = initial_cid
        self._last_fetched_params_hash = None
        self.current_offset = 0
        self.showing_all_items = False
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
        original_credentials = oss_credentials # Store reference to the mutable dict passed in

        def _is_token_expired_error(response_text: str) -> bool:
            return any(err in response_text for err in ('SecurityTokenExpired', 'ExpiredToken', 'InvalidAccessKeyId'))

        def _refresh_oss_credentials(self_instance) -> bool: # Accept 'self' (Uploader instance) explicitly
            # Call the ApiService's refresh method on the Uploader's api_service instance
            if not self_instance.api_service._refresh_access_token(force=False): # Pass 'self' implicitly to _refresh_access_token
                logging.error("Failed to refresh API token via ApiService.")
                return False
            # Fetch new OSS credentials using the Uploader's method
            new_creds = self_instance.get_upload_token() # Call the method on the Uploader instance
            if not new_creds:
                logging.error("Failed to fetch new OSS credentials after token refresh.")
                return False
            # Update the original credentials dictionary passed from the caller
            original_credentials.clear()
            original_credentials.update(new_creds)
            return True

        # Main execution loop with retry logic
        for attempt in range(self.config.UPLOAD_RETRY_COUNT):
            try:
                # --- Construct request components (could be further encapsulated) ---
                creds = original_credentials # Use the potentially updated reference
                access_key_id = creds['AccessKeyId']
                access_key_secret = creds['AccessKeySecret']
                security_token = creds['SecurityToken']
                endpoint = creds['endpoint']

                # Determine protocol and domain from endpoint
                protocol = "https://"
                if endpoint.startswith("http://"):
                    protocol = "http://"
                    endpoint_domain = endpoint[7:]
                elif endpoint.startswith("https://"):
                    endpoint_domain = endpoint[8:]
                else:
                    endpoint_domain = endpoint # Assume domain only if no protocol

                request_host = f"{bucket_name}.{endpoint_domain}"
                full_url = f"{protocol}{request_host}/{quote(object_key)}"

                # Build query string manually to handle None values correctly
                if query_params:
                    # Filter out None values for key-value pairs
                    filtered_params = {k: v for k, v in query_params.items() if v is not None}
                    encoded = urlencode(filtered_params, doseq=True)
                    # Append keys that had None values (as standalone parameters)
                    none_keys = [k for k, v in query_params.items() if v is None]
                    if none_keys:
                        encoded += ('&' if encoded else '') + '&'.join(none_keys)
                    if encoded:
                        full_url += f"?{encoded}"

                # Prepare request headers
                request_headers = headers.copy()
                request_headers.update({
                    "Host": request_host,
                    "x-oss-security-token": security_token,
                    "Content-Type": content_type
                })

                # Calculate Content-MD5 if data is provided
                content_md5 = ""
                if data and isinstance(data, bytes):
                    content_md5 = base64.b64encode(hashlib.md5(data).digest()).decode('utf-8')
                    request_headers["Content-MD5"] = content_md5
                elif 'Content-MD5' in request_headers:
                    content_md5 = request_headers['Content-MD5']

                # Generate signature for the request
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

                # --- Send the HTTP request ---
                logging.debug(f"Attempt {attempt + 1}/{self.config.UPLOAD_RETRY_COUNT}: {method} {full_url}")
                with requests.Session() as session:
                    response = session.request(
                        method.upper(),
                        full_url,
                        headers=request_headers,
                        data=data,
                        timeout=(self.config.DEFAULT_CONNECT_TIMEOUT, self.config.DEFAULT_READ_TIMEOUT)
                    )

                # --- Check for token expiry errors and attempt refresh ---
                if response.status_code == 403 and _is_token_expired_error(response.text):
                    logging.warning(f"OSS credentials expired (attempt {attempt + 1}). Attempting refresh...")
                    if _refresh_oss_credentials(self): # Pass 'self' (the Uploader instance) explicitly
                        time.sleep(2) # Brief pause after refresh before retrying
                        continue # Retry the request
                    else:
                        # Refresh failed, raise the original error
                        response.raise_for_status()

                # If no token error, proceed normally
                response.raise_for_status()
                return response # Success, return the response

            except requests.exceptions.HTTPError as e:
                resp = e.response
                # Specifically check for 403 errors indicating token expiry during HTTPError
                if resp is not None and resp.status_code == 403 and _is_token_expired_error(resp.text):
                    logging.warning(f"OSS token expired in HTTPError (attempt {attempt + 1}). Refreshing...")
                    if _refresh_oss_credentials(self): # Pass 'self' (the Uploader instance) explicitly
                        if attempt < self.config.UPLOAD_RETRY_COUNT - 1:
                            time.sleep(2)
                            continue # Retry after refresh
                    # If refresh failed or this was the last attempt, re-raise
                # For other HTTP errors or if refresh failed, fall through to generic retry
                logging.warning(f"HTTP error (Attempt {attempt + 1}): {e}")

            except requests.exceptions.RequestException as e:
                # Catch other network-related errors
                logging.warning(f"Network error (Attempt {attempt + 1}): {e}")

            # --- Generic retry logic for non-token errors ---
            if attempt < self.config.UPLOAD_RETRY_COUNT - 1:
                logging.info(f"Retrying in {self.config.UPLOAD_RETRY_DELAY_SECONDS} seconds...")
                time.sleep(self.config.UPLOAD_RETRY_DELAY_SECONDS)
            else:
                logging.error("OSS request failed after all retries.")
                # Re-raise the last exception if all retries are exhausted
                raise

        # This line should theoretically not be reached if the loop raises on the last failure,
        # but included for completeness if the exception handling logic changes.
        raise Exception("OSS request failed after all retries")

    def _oss_multipart_initiate(
        self,
        oss_credentials: Dict,
        bucket_name: str,
        object_key: str,
    ) -> str:
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
            if response.status_code in (204, 404):
                return True
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
            if file_size < self.config.CHUNK_SIZE:
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
                part_size = self.config.CHUNK_SIZE
                parts_info = []
                upload_id = self._oss_multipart_initiate(
                    oss_credentials=oss_credentials_for_upload,
                    bucket_name=bucket_name,
                    object_key=object_key,
                )
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
                        sys.stdout.write(f"\rUpload Progress: {total_uploaded_bytes / file_size * 100:.2f}% ({format_bytes_to_human_readable(total_uploaded_bytes)}/{format_bytes_to_human_readable(file_size)})")
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
    def get_upload_token(self) -> Union[Dict, None]:
        result = self.api_service.request(self.config.GET_UPLOAD_TOKEN_API_URL, 'GET')
        if result and result.get("state") and isinstance(result.get("data"), dict):
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
                            if is_item_folder(item):
                                name = _get_item_attribute(item, "fn", "file_name")
                                fid = _get_item_attribute(item, "fid", "file_id")
                                if name and fid:
                                    remote_subfolders[name] = fid
                        offset += len(parent_items)
                        if total_items_in_parent == 0 or offset >= total_items_in_parent:
                            break
                    remote_dir_cache[remote_parent_cid_for_item] = remote_subfolders
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
        if files_for_concurrent_upload:
            logging.info(f"Uploading {len(files_for_concurrent_upload)} files using {self.config.UPLOAD_CONCURRENT_THREADS} concurrent threads.")
            with ThreadPoolExecutor(max_workers=self.config.UPLOAD_CONCURRENT_THREADS) as executor:
                futures = {
                    executor.submit(self._execute_single_file_upload_task, file_path, actual_target_cid): file_path
                    for file_path, actual_target_cid in files_for_concurrent_upload if file_path is not None
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
# =============== 核心类定义 =================
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
        self.RCLONE_TOKEN_FULL_PATH = "my115:token.txt"
        self.USER_AGENT = "Infuse/8.3.5433"
        self.CLIENT_ID = self._get_client_id(4)
        self.DEFAULT_CONNECT_TIMEOUT = 300
        self.DEFAULT_READ_TIMEOUT = 300
        self.MAX_SEARCH_EXPLORE_COUNT = 10000
        self.API_FETCH_LIMIT = 1150
        self.PAGINATOR_DISPLAY_SIZE = 10
        self.ROOT_CID = '0'
        self.ALLOWED_SPECIAL_FILENAME_CHARS = "._- ()[]{}+#@&"
        self.MAX_SAFE_FILENAME_LENGTH = 1150
        self.DEFAULT_TARGET_DOWNLOAD_DIR = self._get_default_download_dir()
        self.JSON_OUTPUT_SUBDIR = 'json'
        self.MOVE_LOG_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)), "move_log.json")
        self.DOWNLOAD_CONCURRENT_THREADS = 10
        self.UPLOAD_CONCURRENT_THREADS = 4
        self.API_RPS_LIMIT = 2
        self.API_CONCURRENT_THREADS = 10
        self.CHUNK_SIZE= 24 * 1024 * 1024
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
            '剧集': 3177795036869964618,
            '电影':3177794855273378210,
            '纪录片': 3112736229787318869,
            '其他文件': 3112736324528257038,
            '综艺节目': 3112736070923860587,
            'nsfw-unzip':3242226173931041749,
            'nsfw': 3090049925983386006
        }
        self.PREDEFINED_UPLOAD_FOLDERS = self.PREDEFINED_SAVE_FOLDERS
        self.DEFAULT_PLAYBACK_STRATEGY = 1
        self.access_token: Union[str, None] = None
        self.show_list_short_form: bool = True
        self.search_more_query: bool = True
        self.enable_concurrent_c_details_fetching: bool = False
        self.MOVE_MAX_FILE_IDS = 100000
        self.MOVE_RATE_LIMIT_FILES_PER_SECOND = 4000
    def _get_default_download_dir(self):
        if "TERMUX_VERSION" in os.environ:
            return os.path.join(os.path.expanduser('~'), 'storage', 'shared', 'Alist', 'aria2')
        else:
            return os.path.join(os.path.expanduser('~'), 'Downloads')
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
_global_api_limiter = None
class ApiService:
    def __init__(self, config: AppConfig):
        self.config = config
        self.token = TokenManager(self.config)
        # 存储当前 Token 和其过期时间戳
        self._current_token: Union[str, None] = None
        self._token_expire_timestamp: float = 0.0
        # 新增：控制 API 是否允许调用的事件
        self._token_valid_event = threading.Event()
        # 新增：控制守护线程退出
        self._stop_token_watcher = threading.Event()
        self._token_watcher_thread: Union[threading.Thread, None] = None

        # 初始化 Token
        token_info = self.token.refresh_and_get_new_token_with_info()
        if token_info:
            self._current_token = token_info["access_token"]
            self._token_expire_timestamp = token_info["_expire_timestamp"]
            self._token_valid_event.set()  # 初始有效
            logging.debug(
                f"[ApiService] Token initialized, expires at: "
                f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._token_expire_timestamp))}"
            )
        else:
            self._current_token = None
            self._token_expire_timestamp = 0.0
            self._token_valid_event.clear()
            logging.error("Failed to initialize access token.")

        # 启动 Token 守护线程
        self._token_watcher_thread = threading.Thread(target=self._token_watcher_loop, daemon=True)
        self._token_watcher_thread.start()

        global _global_api_limiter
        _global_api_limiter = RateLimiter(config.API_RPS_LIMIT)

    def _is_token_expired(self, buffer_seconds: float = 0.0) -> bool:
        """检查当前 Token 是否已过期（或即将过期）"""
        now = time.time()
        return now >= (self._token_expire_timestamp - buffer_seconds)

    def _token_watcher_loop(self):
        """后台线程：主动监控并刷新 token"""
        while not self._stop_token_watcher.is_set():
            try:
                now = time.time()
                # 提前 20 秒进入“即将过期”状态，暂停 API 调用
                if self._token_expire_timestamp > 0 and now >= (self._token_expire_timestamp - 20):
                    logging.info("[TokenWatcher] Token will expire in ~20s. Pausing API calls.")
                    self._token_valid_event.clear()

                    # 等待 token 真正过期
                    sleep_until = self._token_expire_timestamp + 2
                    while time.time() < sleep_until and not self._stop_token_watcher.is_set():
                        time.sleep(0.5)
                    logging.info(f"[TokenWatcher] Refreshing token :{now}")
                    new_token_info = self.token.refresh_and_get_new_token_with_info()
                    if new_token_info and new_token_info.get("access_token"):
                        self._current_token = new_token_info["access_token"]
                        self._token_expire_timestamp = new_token_info["_expire_timestamp"]
                        self._token_valid_event.set() 
                        logging.info(
                            f"[TokenWatcher] Token refreshed successfully, expires at: "
                            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self._token_expire_timestamp))}"
                        )
                    else:
                        logging.error("[TokenWatcher] Token refresh failed. API calls remain paused.")
                        # 可在此处加 retry 逻辑，或直接 exit
                        time.sleep(10)  # 避免频繁失败重试
                        continue

                time.sleep(20)  # 正常监控间隔
            except Exception as e:
                logging.exception(f"[TokenWatcher] Unexpected error: {e}")
                time.sleep(5)

    def __del__(self):
        if hasattr(self, '_stop_token_watcher'):
            self._stop_token_watcher.set()
        if self._token_watcher_thread and self._token_watcher_thread.is_alive():
            self._token_watcher_thread.join(timeout=2)

    def _fetch_concurrent_pages(self, fetch_func: callable, fetch_args_list: List[Dict]) -> List[Any]:
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

    def _build_api_params(self, base_params: Dict, **kwargs) -> Dict:
        combined_params = base_params.copy()
        combined_params.update(kwargs)
        return {k: v for k, v in combined_params.items() if v is not None}

    def _call_api(self, url: str, method: str = 'GET', params: Dict = None, data: Dict = None) -> Union[Dict, None]:
        headers = {
            "Authorization": f"Bearer {self._current_token}",
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
        # ✅ 核心变更：不再检查或刷新 token！只等待事件
        if not self._token_valid_event.wait(timeout=60):  # 最多等 60 秒
            logging.error("[ApiService] Timeout waiting for valid token. Cannot perform API request.")
            return None

        if self._current_token is None:
            logging.error("[ApiService] Access token is None, cannot perform API request.")
            return None

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
                logging.error(f"115 API error {url}: Message: {error_message}.")
                return result
        logging.error(f"API request to {url} failed after {retry_count} attempts.")
        return None

    def fetch_files_in_directory_page(self, cid: str, limit: int = 10, offset: int = 0, **kwargs) -> Tuple[List[Dict], int]:
        params = self._build_api_params({"cid": cid, "limit": limit, "offset": offset}, **kwargs)
        api_response = self.request(self.config.FILE_LIST_API_URL, 'GET', params)
        if api_response and isinstance(api_response.get("data"), list):
            total_count = api_response.get("count", 0)
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
        all_items = []
        main_id_value = base_fetch_kwargs.get(main_id_param_name)
        cleaned_kwargs = {k: v for k, v in base_fetch_kwargs.items() if k != main_id_param_name}
        offsets_to_fetch = []
        actual_total_to_fetch = min(total_count, self.config.MAX_SEARCH_EXPLORE_COUNT if fetch_function == self.search_files else total_count)
        for offset in range(0, actual_total_to_fetch, page_size):
            offsets_to_fetch.append(offset)
        if not offsets_to_fetch and actual_total_to_fetch > 0:
            offsets_to_fetch.append(0)
        fetch_args_list = []
        for offset in offsets_to_fetch:
            page_kwargs = cleaned_kwargs.copy()
            page_kwargs['limit'] = page_size
            page_kwargs['offset'] = offset
            fetch_args_list.append({main_id_param_name: main_id_value, **page_kwargs})
        results = self._fetch_concurrent_pages(fetch_function, fetch_args_list)
        results_with_offset = [(offsets_to_fetch[i], res[0] if res else []) for i, res in enumerate(results)]
        results_with_offset.sort(key=lambda x: x[0])
        for page_offset, page_items in results_with_offset:
            if page_items:
                all_items.extend(page_items)
            else:
                logging.warning(f"Failed to get items for offset {page_offset}, or returned empty data.")
        logging.info(f"General fetching of all items completed, fetched {len(all_items)} items.")
        return all_items

    def search_files(self, search_value: str, limit: int = 10, offset: int = 0, **kwargs) -> Tuple[List[Dict], int]:
        params = self._build_api_params({"search_value": search_value, "limit": limit, "offset": offset}, **kwargs)
        result = self.request(self.config.SEARCH_API_URL, 'GET', params)
        if result and isinstance(result.get("data"), list):
            total_count = result.get("count", 0)
            return result["data"], total_count
        else:
            logging.warning(f"Search for keyword '{search_value}' at offset {offset} failed or returned empty data.")
            return [], 0

    def get_download_link_details(self, file_info: Dict) -> Tuple[Union[str, None], Union[str, None], Union[str, None]]:
        file_name = _get_item_attribute(file_info, "fn", "file_name")
        pick_code = _get_item_attribute(file_info, "pc", "pick_code")
        if is_item_folder(file_info):
            return None, None, f"Skipping folder: {file_name}"
        if not pick_code:
            logging.warning(f"Missing pick_code, cannot get download link. Skipping file: {file_name}")
            return None, None, f"Incomplete file information: {file_name}"
        post_data = self._build_api_params({"pick_code": pick_code})
        result = self.request(self.config.DOWNLOAD_API_URL, 'POST', data=post_data)
        if result:
            data_payload = result.get('data')
            if isinstance(data_payload, dict):
                for pc_key, pc_data in data_payload.items():
                    if isinstance(pc_data, dict) and 'url' in pc_data:
                        url_obj = pc_data['url']
                        if isinstance(url_obj, dict) and 'url' in url_obj and url_obj['url']:
                            download_url = url_obj['url']
                            file_name = f'{pick_code}_{pc_data["file_name"]}'
                            return download_url, file_name, None
                logging.warning(f"API response 'data' has no valid url field for pick_code '{pick_code}'.")
                return None, None, f"Could not parse download link: {file_name}"
            else:
                logging.warning(f"API response 'data' is not a dict. Raw: {data_payload}")
                return None, None, f"API response format error: {file_name}"
        return None, None, f"Failed to get download link for '{file_name}'"

    def move_files(self, file_ids: List[str], to_cid: str, file_count: Union[int, None] = None) -> bool:
        if not file_ids:
            logging.warning("No file IDs provided for move operation.")
            return False
        if not to_cid:
            logging.error("Target CID (to_cid) is missing for move operation.")
            return False
        file_ids_str = ",".join(file_ids)
        post_data = self._build_api_params({
            "file_ids": file_ids_str,
            "to_cid": to_cid
        })
        logging.info("等待移动中")
        result = self.request(self.config.MOVE_API_URL, 'POST', data=post_data)
        time.sleep(10.0 + ((file_count or 0) / self.config.MOVE_RATE_LIMIT_FILES_PER_SECOND))
        if not (result and result.get("state")):
            logging.error("Failed to move files")
            return False
        logging.info("Successfully moved.")
        return True

    def get_item_details(self, file_or_folder_id: str) -> Union[Dict, None]:
        params = self._build_api_params({"file_id": file_or_folder_id})
        result = self.request(self.config.GET_FOLDER_INFO_API_URL, 'GET', params=params)
        return result.get("data") if result and result.get("state") and isinstance(result.get("data"), dict) else None

    def get_items_details_batch(self, file_ids: List[str]) -> Dict[str, Dict]:
        if not file_ids:
            return {}
        fetch_args_list = [{"file_or_folder_id": fid} for fid in file_ids]
        results = self._fetch_concurrent_pages(self.get_item_details, fetch_args_list)
        return {fid: detail for fid, detail in zip(file_ids, results) if detail is not None}

    def create_folder(self, parent_id: str, folder_name: str) -> Tuple[Union[str, None], Union[str, None], Union[str, None]]:
        post_data = {"pid": parent_id,"file_name": folder_name}
        result = self.request(self.config.ADD_FOLDER_API_URL, 'POST', data=post_data)
        if result and result.get("state") and isinstance(result.get("data"), dict):
            data = result["data"]
            new_folder_name = _get_item_attribute(data, "file_name", default_value="Unknown folder")
            new_folder_id = _get_item_attribute(data, "file_id")
            if new_folder_name and new_folder_id:
                return new_folder_id, new_folder_name, None
            return None, None, "API response missing new folder information"
        error_message = result.get('message', 'Unknown error') if result else "API request failed"
        logging.error(f"Failed to create folder '{folder_name}': {error_message}")
        return None, None, error_message

    def rename_file_or_folder(self, file_id: str, new_file_name: str) -> Tuple[bool, Union[str, None], Union[str, None]]:
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
                    logging.info(f"Successfully renamed file/folder ID '{file_id}' to '{updated_file_name}'.")
                    return True, updated_file_name, None
            return True, new_file_name, "Response 'data' missing expected fields"
        error_message = result.get('message', 'Unknown error') if result else 'API request failed'
        logging.error(f"Failed to rename file/folder ID '{file_id}': {error_message}")
        return False, None, error_message

    def delete_files_or_folders(self, file_ids: List[str], parent_id: Union[str, None] = None) -> Tuple[bool, Union[str, None]]:
        if not file_ids:
            return False, "No file IDs provided"
        file_ids_str = ",".join(file_ids)
        post_data = {
            "file_ids": file_ids_str
        }
        if parent_id:
            post_data["parent_id"] = parent_id
        result = self.request(self.config.DELETE_FILE_API_URL, 'POST', data=post_data)
        if result and result.get("state"):
            logging.info(f"Successfully deleted files/folders: {file_ids_str}.")
            return True, None
        error_message = result.get("message", "Unknown error") if result else "API request failed"
        logging.error(f"Failed to delete files/folders {file_ids_str}: {error_message}")
        return False, error_message

    def add_cloud_download_task(self, urls: str, wp_path_id: str = '0') -> Tuple[bool, str, Union[List[Dict], None]]:
        logging.info(f"Adding cloud download tasks to directory '{wp_path_id}'...")
        post_data = {
            "urls": urls,
            "wp_path_id": wp_path_id
        }
        result = self.request(self.config.CLOUD_DOWNLOAD_API_URL, 'POST', data=post_data)
        if not (result and result.get("state")):
            error_message = result.get("message", "Unknown error") if result else "API request failed"
            logging.error(f"Failed to add cloud download tasks: {error_message}")
            return False, error_message, None
        data = result.get("data", [])
        failed_tasks = [task for task in data if not task.get("state")]
        if failed_tasks:
            for task in failed_tasks:
                logging.error(f"Cloud download task failed: URL: {task.get('url', 'Unknown')}, Message: {task.get('message', 'Unknown error')}")
            return False, "Some or all tasks failed, please check logs for details.", data
        return True, "All cloud download tasks successfully added.", data

    def download_file(self, url: str, filename: str, save_path: str) -> Tuple[bool, int, Union[str, None]]:
        safe_filename = _get_safe_filename(filename, self.config)
        full_path = os.path.join(save_path, safe_filename)
        os.makedirs(save_path, exist_ok=True)
        try:
            download_headers = {
                "User-Agent": self.config.USER_AGENT,
                "Referer": self.config.REFERER_DOMAIN
            }
            with requests.get(
                url,
                stream=True,
                timeout=(self.config.DEFAULT_CONNECT_TIMEOUT, self.config.DEFAULT_READ_TIMEOUT),
                headers=download_headers
            ) as r:
                r.raise_for_status()
                total_size = int(r.headers.get('content-length', 0))
                downloaded_size = 0
                start_time = time.time()
                with open(full_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)
                duration = time.time() - start_time
                speed = downloaded_size / duration / (1024 * 1024) if duration > 0 else 0
                return True, downloaded_size, None
        except Exception as e:
            logging.error(f"Failed to download file '{safe_filename}': {e}")
            if os.path.exists(full_path):
                os.remove(full_path)
            return False, 0, f"Download failed: {safe_filename}"
class TokenManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self._refresh_lock = threading.Lock()

    def refresh_and_get_new_token_with_info(self) -> Union[Dict, None]:
        """刷新 Token 并返回包含过期时间戳的信息。"""
        # 使用锁确保同一时间只有一个线程在执行刷新逻辑
        with self._refresh_lock:
            start_time = time.time()
            start_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
            logging.info(f"[TokenManager] Starting token refresh attempt at {start_time_str} (Timestamp: {start_time}).")
            try:
                loaded_data = self._load_token_data_from_remote()

                # 2. 检查加载到的令牌是否有效（未过期）
                if loaded_data:
                    expire_timestamp = loaded_data.get("_expire_timestamp", 0)
                    current_time = time.time()
                    # 如果令牌未过期，直接返回
                    if current_time < expire_timestamp:
                        logging.info(
                            f"[TokenManager] Loaded token is still valid (expires at: "
                            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_timestamp))}). "
                            f"Returning current token info."
                        )
                        return loaded_data
                    else:
                        logging.debug(
                            f"[TokenManager] Loaded token has expired (expired at: "
                            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_timestamp))}). "
                            f"Attempting refresh via API."
                        )
                else:
                    logging.warning("[TokenManager] No valid token data found in local file.")


                if loaded_data and loaded_data.get("refresh_token"):
                    logging.debug("[TokenManager] Attempting API refresh with loaded refresh_token.")
                    new_token_data = self._refresh_access_token_from_api(loaded_data["refresh_token"])
                    if new_token_data:
                        logging.debug("[TokenManager] API refresh successful.")
                        # 计算新的过期时间戳
                        timestamp = int(time.time())
                        expires_in = new_token_data.get("expires_in", 7200)
                        new_token_data["_expire_timestamp"] = timestamp + expires_in
                        self._save_token_data_to_rclone(new_token_data, api_status_code=0)
                        end_time = time.time()
                        end_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))
                        logging.info(
                            f"[TokenManager] Token refreshed successfully at {end_time_str} (Timestamp: {end_time}). "
                            f"Duration: {end_time - start_time:.2f} seconds. Expires at: "
                            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(new_token_data['_expire_timestamp']))}"
                        )
                        return new_token_data
                    else:
                        logging.debug("[TokenManager] API refresh failed.")
                else:
                    logging.warning("[TokenManager] No valid refresh_token found in loaded data for API refresh.")

                # 刷新失败，回退到设备码认证
                logging.info("[TokenManager] Refresh token failed, falling back to device code authentication.")
                new_token_data = self._get_new_tokens_via_device_code() # 这个函数内部有日志，会显示耗时
                if new_token_data:
                    # 计算过期时间戳
                    timestamp = int(time.time())
                    expires_in = new_token_data.get("expires_in", 7200)
                    new_token_data["_expire_timestamp"] = timestamp + expires_in
                    self._save_token_data_to_rclone(new_token_data, api_status_code=0)
                    end_time = time.time()
                    end_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))
                    logging.info(
                        f"[TokenManager] New token (via device code) obtained after refresh failure at {end_time_str} (Timestamp: {end_time}). "
                        f"Duration (since initial attempt): {end_time - start_time:.2f} seconds. Expires at: "
                        f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(new_token_data['_expire_timestamp']))}"
                    )
                    return new_token_data
                else:
                    logging.error("[TokenManager] Device code fallback also failed.")
                    end_time = time.time()
                    end_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))
                    logging.info(
                        f"[TokenManager] Token refresh ultimately failed at {end_time_str} (Timestamp: {end_time}). "
                        f"Duration (since initial attempt): {end_time - start_time:.2f} seconds."
                    )
                    return None
            except Exception as e:
                logging.exception(f"[TokenManager] Unexpected error during refresh attempt: {e}")
                end_time = time.time()
                end_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))
                logging.info(
                    f"[TokenManager] Token refresh failed due to exception at {end_time_str} (Timestamp: {end_time}). "
                    f"Duration (since initial attempt): {end_time - start_time:.2f} seconds."
                )
                return None

    def _load_token_data_from_remote(self) -> Union[Dict, None]:
        # ... (原有加载逻辑，但增加过期时间戳计算)
        command_cat = ["rclone", "cat", self.config.RCLONE_TOKEN_FULL_PATH]
        return_code_cat, stdout_cat, stderr_cat = self._execute_shell_command(command_cat)
        if return_code_cat != 0 or not stdout_cat:
            logging.warning(f"警告: 未能读取远程令牌文件 '{self.config.RCLONE_TOKEN_FULL_PATH}' "
                            f"(返回码: {return_code_cat}, 错误: {stderr_cat.strip()})。")
            return None

        try:
            token_container = json.loads(stdout_cat)
            if isinstance(token_container, dict) and "data" in token_container:
                data = token_container["data"]
                # 计算 expire 时间戳
                timestamp = token_container.get("timestamp", 0)
                expires_in = data.get("expires_in", 7200)
                expire_timestamp = timestamp + expires_in
                result = {
                    **data,
                    "_expire_timestamp": expire_timestamp
                }
                logging.debug(
                    f"[TokenManager] Loaded token data from file, expires at: "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expire_timestamp))}"
                )
                return result
        except Exception as e:
            logging.error(f"解析令牌文件时出错: {e}")
            pass # 任意解析或结构错误都统一处理

        logging.warning(f"警告: 远程文件 '{self.config.RCLONE_TOKEN_FULL_PATH}' 内容无效或缺少 'data' 键。")
        return None

    # --- 保持不变的辅助方法 ---
    def _generate_code_verifier(self, length=128):
        length = 128 # Fixed length for consistency, or use secrets.choice(range(43, 129))
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
            return True
        except Exception as e:
            logging.error(f"保存令牌时发生意外错误: {e}")
            return False

    def _get_new_tokens_via_device_code(self) -> Union[Dict, None]:
        # ... (原有设备码认证逻辑，保持不变)
        code_verifier = self._generate_code_verifier()
        code_challenge = self._generate_code_challenge(code_verifier)
        auth_data = None
        def _fetch_json(url, method='post', **kwargs):
            try:
                resp = requests.request(method, url, **kwargs)
                resp.raise_for_status()
                return resp.json()
            except (requests.RequestException, json.JSONDecodeError) as e:
                logging.error(f"API 请求失败 ({url}): {e}")
                return None

        # 获取设备码
        auth_data = _fetch_json(
            self.config.AUTH_DEVICE_CODE_URL,
            data={
                "client_id": self.config.CLIENT_ID,
                "code_challenge": code_challenge,
                "code_challenge_method": "sha256"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if not auth_data or auth_data.get("code") != 0 or "data" not in auth_data:
            logging.error(f"未能获取设备码。响应: {auth_data}")
            return None
        data = auth_data["data"]
        if not all(k in data for k in ("uid", "qrcode", "time", "sign")):
            logging.error("设备码响应缺少关键数据。")
            return None
        uid, qrcode_content, time_val, sign = data["uid"], data["qrcode"], data["time"], data["sign"]
        print("\n请使用 115 客户端扫描下方二维码进行授权:")
        qrcode_terminal.draw(qrcode_content)
        while True:
            status_data = _fetch_json(
                self.config.QRCODE_STATUS_URL,
                method='get',
                params={"uid": uid, "time": time_val, "sign": sign}
            )
            if not status_data:
                return None
            if status_data.get("data", {}).get("status") == 2:
                break
            time.sleep(5)
        token_data = _fetch_json(
            self.config.DEVICE_CODE_TO_TOKEN_URL,
            data={"uid": uid, "code_verifier": code_verifier},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if token_data and token_data.get("code") == 0 and "data" in token_data:
            return token_data["data"]
        logging.error(f"未能获取初始令牌。响应: {token_data}")
        return None

    def _refresh_access_token_from_api(self, refresh_token_value: str) -> Union[Dict, None]:
        """
        使用 refresh_token 调用 API 刷新 access_token。
        如果刷新成功，返回新的令牌数据（包含 access_token, refresh_token, expires_in 等）。
        如果刷新失败（例如 refresh_token 本身无效或过期），返回 None。
        """
        response = None
        try:
            response = requests.post(
                self.config.REFRESH_TOKEN_URL,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"refresh_token": refresh_token_value} # 使用传入的 refresh_token_value
            )
            response.raise_for_status()
            if not response.text or not response.text.strip():
                logging.error(f"错误: 刷新 API 收到空响应体。")
                return None # 返回 None 表示失败

            result = response.json()
            # API 成功返回
            if result.get("code") == 0 and "data" in result:
                logging.debug("[TokenManager] API 刷新 access_token 成功。")
                return result["data"] # 返回新的令牌数据
            else:
                # API 返回错误
                error_code = result.get("code", -1)
                error_message = result.get('message', 'Unknown error')
                logging.error(f"令牌刷新 API 返回错误。错误码: {error_code}, 信息: {error_message}, 完整响应: {result}")
                # 通常，refresh_token 无效或过期时，API 会返回特定的错误码，例如 10000 或其他。
                # 这里假设 code != 0 意味着 refresh_token 无效，需要回退。
                # 如果有更具体的错误码表示 refresh_token 无效，可以单独处理。
                # 例如： if error_code in [10000, 10001]: # 假设 10001 也是无效刷新令牌的码
                #           logging.info("Refresh token 已失效或无效。")
                #           return None
                # 为了兼容性，目前只要 code != 0 就认为需要回退
                return None # 返回 None 表示刷新失败，需要回退到设备码认证

        except requests.exceptions.RequestException as e:
            # 网络错误、超时等
            logging.error(f"令牌刷新 API 调用失败 (网络错误): {e}")
            # 对于网络错误，可能只是临时问题，但当前逻辑是失败后直接回退。
            # 如果想对网络错误进行重试，可以在这里处理。
            return None # 返回 None 表示刷新失败
        except json.JSONDecodeError:
            # 响应不是 JSON 格式
            logging.error(f"未能解析刷新 API 响应 (非 JSON): {response.text if response else 'No response body'}")
            return None # 返回 None 表示刷新失败
        except Exception as e:
            # 其他意外错误
            logging.error(f"令牌刷新过程中发生未知错误: {e}")
            return None # 返回 None 表示刷新失败
    # --- 可选：如果 ApiService 不再直接调用，可以移除或保留 ---
    def refresh_and_get_new_token(self) -> Union[str, None]:
        token_info = self.refresh_and_get_new_token_with_info()
        return token_info["access_token"] if token_info else None

# =============== 全局通用函数 ===============
def traverse_folder_bfs_concurrent(
    api_service: ApiService,
    config: AppConfig,
    root_cid: str,
    root_name: str,
    item_handler: Callable[[Dict], None] = lambda x: None,
    folder_handler: Callable[[Dict], None] = lambda x: None,
) -> List[Dict]:
    from collections import deque
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    all_items = []
    all_items_lock = threading.Lock()
    visited = set()
    visited_lock = threading.Lock()

    # 全局任务队列（线程安全）
    task_queue = deque()
    task_queue.append((root_cid, root_name, ""))

    with visited_lock:
        visited.add(root_cid)

    def _process_directory(cid: str, name: str, parent_path: str):
        try:
            first_page_items, total = api_service.fetch_files_in_directory_page(
                cid=cid, limit=config.API_FETCH_LIMIT, offset=0, **config.COMMON_BROWSE_FETCH_PARAMS
            )
            if total == 0:
                return [], []

            if total <= config.API_FETCH_LIMIT:
                # 总数小于等于单页限制，第一页已经包含全部内容
                items = []
                subdirs = []
                current_path = join_relative_path(parent_path, name) if parent_path else name
                for item in first_page_items:
                    item_copy = item.copy()
                    rel_path = join_relative_path(current_path, _get_item_attribute(item, "fn", "file_name", default_value="Unknown"))
                    item_copy["_relative_path"] = rel_path
                    items.append(item_copy)
                    if is_item_folder(item):
                        fid = _get_item_attribute(item, "fid", "file_id")
                        if fid:
                            subdirs.append((fid, _get_item_attribute(item, "fn", "file_name", default_value="Unknown")))
                return items, subdirs

            page_size = config.API_FETCH_LIMIT
            remaining_offsets = list(range(page_size, total, page_size))
            def _fetch_page(off):
                items, _ = api_service.fetch_files_in_directory_page(
                    cid=cid, limit=page_size, offset=off, **config.COMMON_BROWSE_FETCH_PARAMS
                )
                return items
            fetch_args = [{"off": off} for off in remaining_offsets]
            remaining_page_results = api_service._fetch_concurrent_pages(lambda off: _fetch_page(off), fetch_args)
            items = []
            subdirs = []
            current_path = join_relative_path(parent_path, name) if parent_path else name

            for item in first_page_items:
                item_copy = item.copy()
                rel_path = join_relative_path(current_path, _get_item_attribute(item, "fn", "file_name", default_value="Unknown"))
                item_copy["_relative_path"] = rel_path
                items.append(item_copy)
                if is_item_folder(item):
                    fid = _get_item_attribute(item, "fid", "file_id")
                    if fid:
                        subdirs.append((fid, _get_item_attribute(item, "fn", "file_name", default_value="Unknown")))

            for page in remaining_page_results:
                if not page: 
                    logging.warning(f"Traverse: A page failed to fetch (offset in remaining_offsets). Skipping.")
                    continue
                for item in page:
                    item_copy = item.copy()
                    rel_path = join_relative_path(current_path, _get_item_attribute(item, "fn", "file_name", default_value="Unknown"))
                    item_copy["_relative_path"] = rel_path
                    items.append(item_copy)
                    if is_item_folder(item):
                        fid = _get_item_attribute(item, "fid", "file_id")
                        if fid:
                            subdirs.append((fid, _get_item_attribute(item, "fn", "file_name", default_value="Unknown")))

            return items, subdirs

        except Exception as e:
            logging.error(f"Error processing directory CID {cid}: {e}")
            return [], []

    with ThreadPoolExecutor(max_workers=config.API_CONCURRENT_THREADS) as executor:
        # 初始任务提交
        futures = {}
        while task_queue or futures:
            # 提交新任务（直到线程池满）
            while task_queue and len(futures) < config.API_CONCURRENT_THREADS:
                cid, name, parent_path = task_queue.popleft()
                future = executor.submit(_process_directory, cid, name, parent_path)
                futures[future] = (cid, name, parent_path)

            if not futures:
                break

            # 等待任意一个任务完成（as_completed 保证最早完成的先处理）
            for future in as_completed(futures):
                cid, name, parent_path = futures.pop(future)
                try:
                    items, subdirs = future.result()
                except Exception as e:
                    logging.error(f"Future for CID {cid} raised exception: {e}")
                    items, subdirs = [], []

                # 1. 收集结果
                if items:
                    with all_items_lock:
                        for item in items:
                            all_items.append(item)
                            if is_item_folder(item):
                                folder_handler(item)
                            else:
                                item_handler(item)

                # 2. 提交子目录任务（去重）
                for sub_cid, sub_name in subdirs:
                    with visited_lock:
                        if sub_cid not in visited:
                            visited.add(sub_cid)
                            task_queue.append((sub_cid, sub_name, join_relative_path(parent_path, name) if parent_path else name))

                break  # 只处理一个完成的任务，立即去提交新任务，实现流水线

    return all_items


# =============== 核心组件（保持 v6.1 架构）==============
class NavigationManager:
    def __init__(self, state: 'BrowserState', api_service: ApiService, config: AppConfig):
        self.state = state
        self.api_service = api_service
        self.config = config
    def navigate_to_cid(self, target_cid: str, title: str = None):
        title = title or f"CID: {target_cid}"
        self.state.current_fetch_function = self.api_service.fetch_files_in_directory_page
        self.state.current_browse_params = self.config.PREDEFINED_FETCH_PARAMS["default_browse"]["params"].copy()
        self.state.current_browse_params["cid"] = target_cid
        self.state.current_folder_id = target_cid
        self.state.title = title
        self.state.current_offset = 0
        self.state.showing_all_items = False
        self.state._last_fetched_params_hash = None
        self._refresh_paginator_data()
    def _refresh_paginator_data(self):
        current_fetch_func = self.state.current_fetch_function
        current_browse_params = self.state.current_browse_params.copy()
        sorted_params = sorted(current_browse_params.items())
        params_hash = str(hash(frozenset(sorted_params)))
        # ✅ 新逻辑：判断“所需 offset 是否已在缓存范围内”，并支持缓存已满（total ≤ 缓存大小）
        current_offset = self.state.current_offset
        cache_start = self.state._api_cache_start_offset
        cache_end = cache_start + len(self.state._api_cache_buffer)
        total = self.state.total_items

        # 情况 1：所需 offset 已在缓存中 → 直接返回
        if (params_hash == self.state._last_fetched_params_hash and
            cache_start <= current_offset < cache_end):
            return

        # 情况 2：缓存已包含全部数据（小目录一次拉完）→ 也直接返回（即使 offset 超界，UI 层应处理）
        if (params_hash == self.state._last_fetched_params_hash and
            len(self.state._api_cache_buffer) >= min(total, self.config.API_FETCH_LIMIT) and
            total <= len(self.state._api_cache_buffer)):
            return

        # 否则：需要新请求 → 按需计算 offset（可非整页对齐！）
        required_api_fetch_offset = current_offset  # 👈 不再强制对齐页！
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
class DownloadManager:
    def __init__(self, api_service: ApiService, config: AppConfig, state: 'BrowserState'):
        self.api_service = api_service
        self.config = config
        self.state = state
    def download_single_item_and_link(self, item: Dict, full_target_path: str) -> Tuple[bool, str, Union[str, None]]:
        file_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown File")
        #file_id = _get_item_attribute(item, "fid", "file_id", default_value="unknown_id")
        download_url, _, error_message = self.api_service.get_download_link_details(item)
        if download_url:
            save_dir = os.path.dirname(full_target_path)
            success, downloaded_size, download_error_msg = self.api_service.download_file(download_url, os.path.basename(full_target_path), save_dir)
            return success, file_name, download_error_msg
        else:
            return False, file_name, error_message or "Failed to get download link"
    def execute_download_queue(self, items_with_paths_to_download: List[Tuple[Dict, str]], prefix_item_name: str = "Download"):
        if not items_with_paths_to_download:
            return
        with ThreadPoolExecutor(max_workers=self.config.DOWNLOAD_CONCURRENT_THREADS) as executor:
            futures = [
                executor.submit(self.download_single_item_and_link, item, full_target_path)
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
class UploadManager:
    def __init__(self, config: AppConfig, api_service: ApiService):
        self.config = config
        self.api_service = api_service
    def upload_paths_to_target(self, local_paths: List[str], target_cid: str) -> List[Tuple[bool, str]]:
        uploader = Uploader(self.config, self.api_service)
        return uploader.upload_paths_to_target(local_paths, target_cid)
class FolderOperationService:
    def __init__(self, api_service: ApiService, config: AppConfig, state: 'BrowserState', browser: 'FileBrowser'):
        self.api_service = api_service
        self.config = config
        self.state = state
        self.browser = browser
    def _get_estimated_total_items(self, details: dict) -> int:
        try:
            count = int(details.get("count", 0) or 0)
            folder_count = int(details.get("folder_count", 0) or 0)
            return max(0, count + folder_count)
        except (ValueError, TypeError):
            return 0
    def _get_original_folder_name_from_paths(self, cid: str) -> str:
        if not cid or cid == '0':
            return "Root"
        details = self.api_service.get_item_details(cid)
        if not details or not isinstance(details, dict):
            return "Unknown"
        paths = details.get("paths", [])
        if not paths or not isinstance(paths, list):
            return "Unknown"
        folder_names = []
        for p in paths:
            name = _get_item_attribute(p, "file_name")
            if name and name not in ["Root", "0"]:
                folder_names.append(name)
        if not folder_names:
            return "Unknown"
        raw_name = folder_names[-2]
        import re
        cleaned = re.sub(r'^\[\d+/\d+\]\s*', '', raw_name)
        cleaned = re.sub(r'\s*[-—]\s*(分组\d+（共\d+组）|块\d+（\d+-\d+）)$', '', cleaned)
        return cleaned.strip() or raw_name
    def execute_page1(self, current_page_items: List[Dict]) -> str:
        browser = self._get_browser()
        browser._fetch_all_items_and_update_state()
        all_items = browser.state._all_items_cache
        if not all_items:
            logging.warning("当前目录下没有子文件夹，无法分页。")
            return CMD_CONTINUE_INPUT
        folder_items = [(item["fid"], item["fn"], item) for item in all_items if is_item_folder(item) and "fid" in item and "fn" in item]
        if not folder_items:
            logging.warning("当前目录下没有子文件夹，无法分页。")
            return CMD_CONTINUE_INPUT
        fids = [fid for fid, _, _ in folder_items]
        details_map = self.api_service.get_items_details_batch(fids)
        folder_stats = []
        for (fid, name, _), details in zip(folder_items, [details_map.get(fid) for fid in fids]):
            if details:
                total = self._get_estimated_total_items(details)
                folder_stats.append((fid, name, total))
        folder_stats.sort(key=lambda x: x[2], reverse=True)
        MAX_LIMIT = 100000
        groups = []
        for fid, name, total in folder_stats:
            placed = False
            for group in groups:
                if group[1] + total <= MAX_LIMIT:
                    group[0].append((fid, name, total))
                    group[1] += total
                    placed = True
                    break
            if not placed:
                groups.append([[(fid, name, total)], total])
        current_cid = browser.state.current_folder_id
        for idx, (group_items, _) in enumerate(groups, start=1):
            new_folder_name = f"[1/2] {self._get_original_folder_name_from_paths(current_cid)} - 分组{idx}（共{len(groups)}组）"
            new_cid, _, err = self.api_service.create_folder(current_cid, new_folder_name)
            if not new_cid:
                logging.error(f"❌ 无法创建分页文件夹 '{new_folder_name}'，跳过该组。")
                continue
            fids_to_move = [fid for fid, _, _ in group_items]
            success = self.api_service.move_files(fids_to_move, new_cid)
            if success:
                logging.info(f"✅ 分页-{idx} 完成，共移动 {len(fids_to_move)} 个文件夹。")
            else:
                logging.warning(f"⚠️ 分页-{idx} 移动失败！")
        logging.info("✨ 分页归档操作完成！")
        browser.state._last_fetched_params_hash = None
        return CMD_RENDER_NEEDED
    def execute_page2(self, current_page_items: List[Dict]) -> str:
        self.browser._fetch_all_items_and_update_state()
        all_items = self.browser.state._all_items_cache
        if not all_items:
            logging.warning("page2: 当前上下文无任何项目，无法分页。")
            return CMD_CONTINUE_INPUT
        current_cid = self.browser.state.current_folder_id
        if current_cid == '0':
            original_name = "Root"
        else:
            details = self.api_service.get_item_details(current_cid)
            if details and isinstance(details, dict):
                original_name = details.get("file_name", "Unknown")
            else:
                original_name = "Unknown"
        total_items = len(all_items)
        GROUP_SIZE = 200
        total_groups = (total_items + GROUP_SIZE - 1) // GROUP_SIZE
        current_cid = self.browser.state.current_folder_id
        for group_idx in range(total_groups):
            start = group_idx * GROUP_SIZE
            end = min(start + GROUP_SIZE, total_items)
            group_items = all_items[start:end]
            fids_to_move = extract_fids(group_items)
            if not fids_to_move:
                continue
            start_num = start + 1
            end_num = min(start + GROUP_SIZE, total_items)
            folder_name = f"[2/2] {original_name} - 块{group_idx+1:03d}（{start_num}-{end_num}）"
            new_cid, _, err = self.api_service.create_folder(current_cid, folder_name)
            if not new_cid:
                continue
            success = self.api_service.move_files(fids_to_move, new_cid)
            if success:
                logging.info(f"✅ 第{group_idx + 1}组移动成功。")
            else:
                logging.error(f"❌ 第{group_idx + 1}组移动失败！")
        logging.info("✨ page2 分页归档操作全部完成！")

        # ✅ 强制刷新当前目录数据：清缓存 + 触发重新拉取
        self.browser.state._api_cache_buffer = []          # 清空缓存
        self.browser.state._api_cache_start_offset = 0
        self.browser.state._last_fetched_params_hash = None
        self.browser.state.current_offset = 0              # 回到第一页
        self.browser.state.showing_all_items = False       # 退出“全量模式”
        self.browser.state._all_items_cache = []           # 清空全量缓存

        # ✅ 主动刷新数据（等价于用户手动按 'ls'）
        self.browser._refresh_paginator_data()

        return CMD_RENDER_NEEDED
    def _get_browser(self):
        return self.browser
class PredefinedFolderNavigator:
    def __init__(self, config: AppConfig, navigation_manager: NavigationManager):
        self.config = config
        self.nav = navigation_manager
    def handle_jump_command(self, action_choice: str, predefined_list: List[Tuple[str, str]]) -> str:
        parts = action_choice.split()
        if len(parts) == 1:
            logging.info("\n【预设收藏文件夹】")
            for i, (name, cid) in enumerate(predefined_list):
                logging.info(f"[{i}] {name} (CID: {cid})")
            logging.info("请输入 'jump <索引>' 跳转，或输入其他命令继续。")
            return CMD_CONTINUE_INPUT
        elif len(parts) == 2:
            try:
                idx = int(parts[1])
                if 0 <= idx < len(predefined_list):
                    folder_name, folder_cid = predefined_list[idx]
                    logging.info(f"Jumping to predefined folder: {folder_name} (CID: {folder_cid})")
                    self.nav.navigate_to_cid(folder_cid, title=f"Predefined: {folder_name}")
                    return CMD_RENDER_NEEDED
                else:
                    logging.warning(f"Index {idx} out of range (0–{len(predefined_list)-1})")
                    return CMD_CONTINUE_INPUT
            except ValueError:
                logging.warning("Invalid index. Please enter a number.")
                return CMD_CONTINUE_INPUT
        else:
            logging.warning("Usage: jump [index]")
            return CMD_CONTINUE_INPUT
class CommandHandler:
    def __init__(self, browser: 'FileBrowser'):
        self.browser = browser
        self.config = browser.config
        self.state = browser.state
        self.api_service =browser.api_service
        self.nav_manager = NavigationManager(self.state, self.api_service, self.config)
        self.download_manager = DownloadManager(self.api_service, self.config, self.state)
        self.upload_manager = UploadManager(self.config, self.api_service)
        self.folder_op_service = FolderOperationService(self.api_service, self.config, self.state, self.browser)
        self.predefined_nav = PredefinedFolderNavigator(self.config, self.nav_manager)
    def handle_num(self, action_choice: str, page_items: List[Dict]) -> str: 
        parts = action_choice.split(' ', 1)
        if len(parts) != 2:
            logging.warning("Usage: num <number>")
            return CMD_CONTINUE_INPUT
        try:
            new_size = int(parts[1])
            if new_size <= 0:
                logging.warning("Display size must be a positive integer.")
                return CMD_CONTINUE_INPUT
            self.config.PAGINATOR_DISPLAY_SIZE = new_size
            logging.info(f"Display size set to {new_size}.")
            self.state.current_offset = 0 
            return CMD_RENDER_NEEDED
        except ValueError:
            logging.warning(f"Invalid number: '{parts[1]}'. Please enter a valid integer.")
            return CMD_CONTINUE_INPUT
    def handle_jump(self, action_choice: str, page_items: List[Dict]) -> str:
        predefined_list = get_predefined_folder_list(self.config.PREDEFINED_SAVE_FOLDERS)
        return self.predefined_nav.handle_jump_command(action_choice, predefined_list)
    def handle_cd(self, action_choice: str, page_items: List[Dict]) -> str:
        user_input_parts = action_choice.split()
        if len(user_input_parts) < 2:
            logging.warning("Usage: cd <index> or cd ..")
            return CMD_CONTINUE_INPUT
        target_input = user_input_parts[1]
        if target_input == '..':
            return self.handle_b()
        else:
            try:
                index = int(target_input)
                if 0 <= index < len(page_items):
                    selected_item = page_items[index]
                    target_cid = _get_item_attribute(selected_item, "pid", "parent_id", default_value=self.config.ROOT_CID)
                    folder_name = f"Parent of '{_get_item_attribute(selected_item, 'fn', 'file_name', default_value='Unknown File')}'"
                    self.state.parent_cid_stack.append(self.state.create_snapshot())
                    self.nav_manager.navigate_to_cid(target_cid, title=f"Folder '{folder_name}' List")
                    logging.info(f"Entering parent directory of file: '{folder_name}' (CID: {target_cid}).")
                    return CMD_RENDER_NEEDED
                else:
                    logging.warning(f"Index {index} is out of current page range.")
                    return CMD_CONTINUE_INPUT
            except ValueError:
                logging.warning("Invalid index. Please provide a numeric index or '..'.")
                return CMD_CONTINUE_INPUT
    def handle_b(self) -> str:
        if self.state.parent_cid_stack:
            prev_state = self.state.parent_cid_stack.pop()
            self.state.restore_from_snapshot(prev_state)
            return CMD_RENDER_NEEDED
        else:
            return CMD_RENDER_NEEDED
    def handle_d(self, action_choice: str, page_items: List[Dict]) -> str:
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
            self.download_manager.execute_download_queue(files_to_download_immediately, "Individual File Download")
        if folders_to_process:
            for folder in folders_to_process:
                folder_name = _get_item_attribute(folder, "fn", "file_name", default_value="Unknown Folder")
                recursive_download_path = os.path.join(self.state.target_download_dir, folder_name)
                self.browser.recursively_download_folder(folder, recursive_download_path, folder_name)
                logging.info(f"--- Folder '{folder_name}' processing completed ---")
        return CMD_RENDER_NEEDED
    def handle_page1(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.folder_op_service.execute_page1(page_items)
    def handle_page2(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.folder_op_service.execute_page2(page_items)
    def handle_i(self, action_choice: str, page_items: List[Dict]) -> str:
        indices_str = action_choice.split(' ', 1)[1]
        selected_indices = parse_indices_input(indices_str, len(page_items))
        if not selected_indices:
            logging.warning("No items selected to query for details.")
            return CMD_CONTINUE_INPUT
        items_to_fetch_details = [(idx, page_items[idx]) for idx in selected_indices if _get_item_attribute(page_items[idx], "fid", "file_id")]
        if not items_to_fetch_details:
            logging.warning("Selected items lack valid IDs, cannot fetch details.")
            return CMD_CONTINUE_INPUT
        items_list = [item for _, item in items_to_fetch_details]
        enrich_items_with_details(items_list, self.api_service)
        self.state._force_full_display_next_render = True
        return CMD_RENDER_NEEDED
    def handle_a(self) -> str:
        self.browser._fetch_all_items_and_update_state()
        return CMD_RENDER_NEEDED
    def handle_upload(self) -> str:
        import builtins
        builtins._current_browser = self.browser  # for hack in FolderOperationService
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
        target_cid = _prompt_for_folder_selection(
            current_folder_id=self.state.current_folder_id,
            predefined_folders=self.config.PREDEFINED_UPLOAD_FOLDERS,
            prompt_message="\n--- 请选择上传目标文件夹 ---"
        )
        if target_cid is None:
            logging.info("未选择目标文件夹，上传任务已取消。")
            return CMD_CONTINUE_INPUT
        upload_results = self.upload_manager.upload_paths_to_target(local_paths_to_upload, target_cid)
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
    # 其他命令直接调用 FileBrowser 的公共方法
    def handle_v(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.browser.v(action_choice, page_items)
    def handle_g(self, action_choice: str, *args) -> str:
        return self.browser.g(action_choice, *args)
    def handle_p(self) -> str:
        return self.browser.p()
    def handle_n(self) -> str:
        return self.browser.n()
    def handle_t(self) -> str:
        return self.browser.t()
    def handle_mc(self) -> str:
        return self.browser.mc()
    def handle_f(self, action_choice: str, *args) -> str:
        return self.browser.f(action_choice, *args)
    def handle_s(self) -> str:
        return self.browser.s()
    def handle_index_selection(self, action_choice: str, page_items_to_display: List[Dict]) -> str:
        return self.browser.index_selection(action_choice, page_items_to_display)
    def handle_h(self):
        self.browser.h()
    def handle_save(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.browser.save(action_choice, page_items)
    def handle_m(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.browser.m(action_choice, page_items)
    def handle_mm(self) -> str:
        return self.browser.mm()
    def handle_merge(self) -> str:
        return self.browser.merge()
    def handle_up(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.browser.up(action_choice, page_items)
    def handle_add(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.browser.add(action_choice, page_items)
    def handle_rename(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.browser.rename(action_choice, page_items)
    def handle_del(self, action_choice: str, page_items_to_display: List[Dict]) -> str:
        return self.browser.del_(action_choice, page_items_to_display)
    def handle_cloud(self) -> str:
        return self.browser.cloud()
    def handle_c(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.browser.c(action_choice, page_items)
    def handle_rs(self, action_choice: str, page_items: List[Dict]) -> str:
        return self.browser.rs(action_choice, page_items)
class CommandProcessor:
    def __init__(self, command_handler: CommandHandler):
        self.handler = command_handler
        self.command_map = {
            'p': self.handler.handle_p,
            'n': self.handler.handle_n,
            'a': self.handler.handle_a,
            'merge': self.handler.handle_merge,
            'b': self.handler.handle_b,
            'q': lambda *args: CMD_EXIT,
            's': self.handler.handle_s,
            't': self.handler.handle_t,
            'mc': self.handler.handle_mc,
            'mm': self.handler.handle_mm,
            'ls': lambda *args: CMD_RENDER_NEEDED,
            'h': self.handler.handle_h,
            'cloud': self.handler.handle_cloud,
            'upload': self.handler.handle_upload,
        }
        self.prefix_command_map = {
            'g': self.handler.handle_g,
            'f': self.handler.handle_f,
            'd': self.handler.handle_d,
            'v': self.handler.handle_v,
            'page1': self.handler.handle_page1,
            'page2': self.handler.handle_page2,
            'rs': self.handler.handle_rs,
            'i': self.handler.handle_i,
            'c': self.handler.handle_c,
            'up': self.handler.handle_up,
            'm': self.handler.handle_m,
            'save': self.handler.handle_save,
            'cd': self.handler.handle_cd,
            'add': self.handler.handle_add,
            'rename': self.handler.handle_rename,
            'del': self.handler.handle_del,
            'jump': self.handler.handle_jump, 
             'num': self.handler.handle_num, 
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
        return self.handler.handle_index_selection(user_input, page_items)
class BrowserState:
    def __init__(self, initial_cid: str, initial_browse_params: Dict, initial_api_chunk: List[Dict], total_items: int, config: AppConfig):
        self.config = config
        self.title = "Root"
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
            start = self.current_offset
            end = start + self.config.PAGINATOR_DISPLAY_SIZE
            # ✅ 添加安全边界：不超过缓存范围 & 不超过 total
            cache_start = self._api_cache_start_offset
            cache = self._api_cache_buffer
            start_in_cache = max(0, start - cache_start)
            end_in_cache = min(len(cache), end - cache_start)
            if start_in_cache >= len(cache) or start_in_cache >= end_in_cache:
                return []  # 空页（正常翻页超界），不触发重拉
            return cache[start_in_cache:end_in_cache]
class UIRenderer:
    def __init__(self, config: AppConfig, state: BrowserState):
        self.config = config
        self.state = state
    def display_paginated_items_list(self, page_items_to_display: List[Dict], force_full_display: bool = False):
        logging.info(f"--- {self.state.title}---")
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
                        size_bytes=size_bytes/(1024 * 1024 *1024)
                        if size_bytes <= 0.02:
                            colored_name = f"{COLOR_SIZE_SMALL}{name_value}{COLOR_RESET}"
                        elif size_bytes <= 1:
                            colored_name = f"{COLOR_SIZE_MEDIUM}{name_value}{COLOR_RESET}"
                        elif size_bytes <= 6:
                            colored_name = f"{COLOR_SIZE_LARGE}{name_value}{COLOR_RESET}"
                        elif size_bytes <= 20:
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
        logging.info("--- End ---")
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
            'jump [索引]': '跳转到预设收藏文件夹。无参数时列出所有预设。',
            'num <数量>': '设置每页显示的项目数量。',
            'h': '显示本帮助信息。',
            'q': '退出程序。',
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
        logging.info("    - jump <索引>")
        logging.info("    - q：执行完前面命令后直接退出（不进入交互）")
        logging.info("\n  注意：命令链中若未包含 'q'，所有参数执行完毕后会自动进入交互模式。")
        logging.info("\n--------------------------")

class FileBrowser:
    def __init__(self, initial_cid: str, initial_browse_params: Dict, initial_api_chunk: List[Dict], total_items: int, config: AppConfig, api_service: ApiService = None):
        self.config = config
        # 使用传入的 api_service 或创建新的
        self.api_service = api_service if api_service else ApiService(self.config)
        self.state = BrowserState(initial_cid, initial_browse_params, initial_api_chunk, total_items, self.config)
        self.ui_renderer = UIRenderer(self.config, self.state)
        self.command_handler = CommandHandler(self)
        self.command_processor = CommandProcessor(self.command_handler)
        self.state.current_fetch_function = self.api_service.fetch_files_in_directory_page
    def _navigate_to_cid(self, target_cid: str, title: str = None):
        self.command_handler.nav_manager.navigate_to_cid(target_cid, title)
    def _fetch_all_items_and_update_state(self):
        total_to_fetch = self.state.explorable_count
        main_param_name = 'cid' if self.state.current_fetch_function == self.api_service.fetch_files_in_directory_page else 'search_value'
        all_items = self.api_service._fetch_all_items_general(
            fetch_function=self.state.current_fetch_function,
            base_fetch_kwargs=self.state.current_browse_params,
            total_count=total_to_fetch,
            page_size=self.config.API_FETCH_LIMIT,
            main_id_param_name=main_param_name
        )
        self.state._all_items_cache = all_items
        self.state.total_items = len(all_items)
        self.state.explorable_count = self.state.total_items
        self.state.showing_all_items = True
        self.state.current_offset = 0
        self.state.title = f"{self.state.title} All Items List"
    def _refresh_paginator_data(self):
        self.command_handler.nav_manager._refresh_paginator_data()
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
        confirm_choice = input(f"Confirm playing '{file_name}' with Infuse (current Infuse playback might be replaced)? (y/n): ").strip().lower()
        if confirm_choice == "y":
            try:
                subprocess.run(['open', infuse_scheme_url], check=True)
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                logging.error(f"Failed to open Infuse: {e}")
                logging.info(f"Manually open this URL: {infuse_scheme_url}")
    def _encode_url_for_infuse_param(self, content_url: str) -> str:
        encoded_content_url = urllib.parse.quote(content_url, safe='')
        return f"url={encoded_content_url}"
    def recursively_download_folder(self, folder_info: Dict, current_download_path: str, prefix_item_name: str = "Current Task"):
        folder_id = _get_item_attribute(folder_info, "fid", "file_id")
        folder_name = _get_item_attribute(folder_info, "fn", "file_name", default_value="Unknown Folder")
        os.makedirs(current_download_path, exist_ok=True)
        all_files_to_download = []
        def item_handler(item):
            file_relative_path = item.get("_relative_path", item.get("fn", "Unknown"))
            full_target_path = os.path.join(current_download_path, file_relative_path)
            all_files_to_download.append((item, full_target_path))
        def folder_handler(folder):
            folder_name = _get_item_attribute(folder, "fn", "file_name", default_value="Unknown Folder")
            relative_path = folder.get("_relative_path", folder_name)
            full_dir_path = os.path.join(current_download_path, relative_path)
            os.makedirs(full_dir_path, exist_ok=True)
        _ = traverse_folder_bfs_concurrent(
            api_service=self.api_service,
            config=self.config,
            root_cid=folder_id,
            root_name="",
            item_handler=item_handler,
            folder_handler=folder_handler
        )
        if all_files_to_download:
            self._create_download_directories(all_files_to_download)
            self.command_handler.download_manager.execute_download_queue(
                all_files_to_download,
                prefix_item_name=folder_name
            )
    def _create_download_directories(self, files_to_download: List[Tuple[Dict, str]]):
        directories_created = set()
        for item, full_file_path in files_to_download:
            file_dir = os.path.dirname(full_file_path)
            if file_dir not in directories_created:
                try:
                    os.makedirs(file_dir, exist_ok=True)
                    directories_created.add(file_dir)
                except OSError as e:
                    logging.error(f"Failed to create directory {file_dir}: {e}")
    def _concurrent_traverse_folder(self, root_cid: str, root_name: str) -> List[Dict]:
        return traverse_folder_bfs_concurrent(
            api_service=self.api_service,
            config=self.config,
            root_cid=root_cid,
            root_name=root_name
        )
    def c(self, action_choice: str, page_items: List[Dict]) -> str:
        indices_str = action_choice.split(' ', 1)[1]
        selected_indices = parse_indices_input(indices_str, len(page_items))
        if not selected_indices:
            logging.warning("Invalid collection info index selection.")
            return CMD_CONTINUE_INPUT
        items_to_collect = [page_items[idx] for idx in selected_indices]
        for item_info in items_to_collect:
            item_id = _get_item_attribute(item_info, "fid", "file_id")
            item_name = _get_item_attribute(item_info, "fn", "file_name", default_value="Unknown")
            if not item_id:
                logging.error(f"Item '{item_name}' has no valid ID, skipping.")
                continue
            if is_item_folder(item_info):
                all_collected_items = self._concurrent_traverse_folder(item_id, item_name)
            else:
                item_copy = item_info.copy()
                item_copy["_relative_path"] = item_name
                all_collected_items = [item_copy]
            if self.config.enable_concurrent_c_details_fetching:
                enrich_items_with_details(all_collected_items, self.api_service)
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

    def rs(self, action_choice: str, page_items: List[Dict]) -> str:
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

        root_folders = []
        for idx in selected_indices:
            item = page_items[idx]
            if not is_item_folder(item):
                file_name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown")
                logging.warning(f"Skipping non-folder item: '{file_name}'.")
                continue
            fid = _get_item_attribute(item, "fid", "file_id")
            name = _get_item_attribute(item, "fn", "file_name", default_value="Unknown")
            if fid:
                root_folders.append((fid, name))

        if not root_folders:
            logging.warning("No valid folders to scan.")
            return CMD_CONTINUE_INPUT

        logging.info(f"Recursively scanning {len(root_folders)} folder(s) for size <= {threshold_str} ({threshold_bytes} bytes)...")

        all_items = []
        with ThreadPoolExecutor(max_workers=self.config.API_CONCURRENT_THREADS) as executor:
            # Submit all traverse tasks
            future_to_folder = {executor.submit(self._concurrent_traverse_folder, fid, name): (fid, name) for fid, name in root_folders}
            # Collect results as they complete
            for future in as_completed(future_to_folder):
                fid, name = future_to_folder[future]
                try:
                    items = future.result()
                    all_items.extend(items)
                except Exception as e:
                    logging.error(f"Error traversing folder '{name}' (ID: {fid}): {e}")

        # --- 修正：计算每个文件夹的总大小（包含其内部所有文件和子文件夹的大小） ---
        folder_sizes = defaultdict(int) # 存储每个文件夹路径的累计文件大小（不包含子文件夹大小）
        file_items = [item for item in all_items if not is_item_folder(item)]

        def process_file(item):
            """处理单个文件，返回其路径列表和大小"""
            file_size_raw = _get_item_attribute(item, "fs", "file_size")
            if file_size_raw is not None:
                try:
                    file_size = int(file_size_raw)
                except (ValueError, TypeError):
                    logging.warning(f"Could not parse file size for '{_get_item_attribute(item, 'fn', 'file_name')}'. Skipping.")
                    return [], 0
                current_path = item.get("_relative_path", "")
                if not current_path:
                    logging.warning(f"File item missing '_relative_path': {_get_item_attribute(item, 'fn', 'file_name')}")
                    return [], 0
                # 计算父路径列表
                path_parts = current_path.split('/')
                parent_paths = []
                for i in range(len(path_parts)):
                    parent_path = '/'.join(path_parts[:i]) if i > 0 else '' # 根目录用空字符串表示
                    parent_paths.append(parent_path)
                return parent_paths, file_size
            return [], 0

        with ThreadPoolExecutor(max_workers=self.config.API_CONCURRENT_THREADS) as executor:
            # Submit all file processing tasks
            future_to_file = {executor.submit(process_file, item): item for item in file_items}
            # Collect results as they complete
            for future in as_completed(future_to_file):
                parent_paths, size = future.result()
                for parent_path in parent_paths:
                    folder_sizes[parent_path] += size

        # 初始化所有文件夹的大小（包括空文件夹）
        for item in all_items:
            if is_item_folder(item):
                folder_path = item.get("_relative_path", "")
                if folder_path not in folder_sizes: # Only initialize if not already computed via files
                    folder_sizes[folder_path] = 0

        # --- 新增逻辑：计算包含子文件夹的总大小 ---
        # 首先，构建一个映射：子文件夹路径 -> [父文件夹路径列表]
        parent_map = defaultdict(list)
        for item in all_items:
             if is_item_folder(item):
                 child_path = item.get("_relative_path", "")
                 # 检查其父路径
                 parts = child_path.split('/')
                 for i in range(len(parts), 0, -1): # 从最长路径开始向上找
                     parent_path = '/'.join(parts[:i-1]) if i > 1 else ''
                     if parent_path != child_path: # 确保不是自己
                         parent_map[child_path].append(parent_path)
                         break # 找到第一个父级就停止

        # 构建文件夹到其直接子文件夹的映射（用于自底向上计算）
        children_map = defaultdict(list)
        for item in all_items:
            if is_item_folder(item):
                child_path = item.get("_relative_path", "")
                parts = child_path.split('/')
                if len(parts) > 0:
                    parent_path_parts = parts[:-1]
                    parent_path = '/'.join(parent_path_parts) if parent_path_parts else ''
                    if parent_path != child_path:
                        children_map[parent_path].append(child_path)

        # 计算包含子文件夹的总大小：自底向上
        # 先处理叶子节点（没有子文件夹的文件夹），它们的大小就是 folder_sizes 中的值
        # 然后处理上层节点，将其大小加上所有子节点的（已计算好的）总大小
        all_folder_paths = set(folder_sizes.keys())
        sorted_paths = sorted(all_folder_paths, key=lambda x: x.count('/'), reverse=True) # 按路径深度降序排列

        total_folder_sizes = folder_sizes.copy() # 从仅文件大小开始

        for path in sorted_paths:
             direct_file_size = folder_sizes[path]
             child_folders = children_map.get(path, [])
             child_total_size = sum(total_folder_sizes.get(child_path, 0) for child_path in child_folders)
             total_folder_sizes[path] = direct_file_size + child_total_size

        # --- 修正：筛选逻辑使用 total_folder_sizes ---
        final_results = []
        for item in all_items:
            if is_item_folder(item):
                path = item.get("_relative_path", "")
                size_bytes = total_folder_sizes.get(path, 0) # 使用包含子文件夹的总大小
                size_display = format_bytes_to_human_readable(size_bytes)
                if size_bytes <= threshold_bytes:
                    fid = _get_item_attribute(item, "fid", "file_id")
                    if fid:
                        final_results.append((path, size_display, fid, size_bytes)) # Add size_bytes for sorting later
                    else:
                        logging.warning(f"Folder item missing 'fid': {path}")

        if not final_results:
            logging.info(f"No folders found with size <= {threshold_str}.")
            return CMD_CONTINUE_INPUT

        # === 修改：按是否为 0B 分组 ===
        nonzero_folders = []
        zero_folders = []
        for entry in final_results:
            path, size_display, fid, size_bytes = entry
            if size_bytes == 0:
                zero_folders.append(entry)
            else:
                nonzero_folders.append(entry)

        # 按大小排序（非零部分）
        nonzero_folders.sort(key=lambda x: x[3])  # x[3] is size_bytes
        # zero_folders 保持原顺序或按路径排序（可选）
        zero_folders.sort(key=lambda x: x[0])  # 按路径名排序

        logging.info(f"--- Folders with size <= {threshold_str} ---")
        logging.info(f"--- [Non-zero Folders] ({len(nonzero_folders)} found) ---")
        display_list = []
        for i, (path, size, fid, _) in enumerate(nonzero_folders):
            logging.info(f"[{i}] {size:>10}  {path}")
            display_list.append((path, size, fid))

        if zero_folders:
            logging.info(f"--- [Zero-sized Folders] ({len(zero_folders)} found) ---")
            zero_start_index = len(nonzero_folders)
            for j, (path, size, fid, _) in enumerate(zero_folders):
                idx = zero_start_index + j
                logging.info(f"[{idx}] {size:>10}  {path}")
                display_list.append((path, size, fid))
        else:
            logging.info("--- [Zero-sized Folders] (none) ---")

        logging.info("--- End of Results ---")

        # 后续的交互删除逻辑使用 display_list 作为统一列表
        # 注意：display_list 顺序 = [nonzero..., zero...]
        if not display_list:
            return CMD_CONTINUE_INPUT

        while True:
            try:
                user_input = input("In 'rs' delete mode. Enter 'del <index>' to delete, or 'q' to quit: ").strip()
            except (EOFError, KeyboardInterrupt):
                logging.info("Operation cancelled by user.")
                return CMD_RENDER_NEEDED
            if not user_input:
                continue
            if user_input.lower() == 'q':
                logging.info("Exiting 'rs' delete mode.")
                return CMD_RENDER_NEEDED
            if user_input.lower().startswith('del '):
                try:
                    idx_input = user_input.split(' ', 1)[1].strip()
                    selected_del_indices = parse_indices_input(idx_input, len(display_list))
                    if not selected_del_indices:
                        logging.warning("Invalid index format.")
                        continue
                    to_delete = []
                    for idx in selected_del_indices:
                        if 0 <= idx < len(display_list):
                            full_path, _, fid = display_list[idx]
                            to_delete.append((idx, full_path, fid))
                        else:
                            logging.warning(f"Index {idx} out of range.")
                    if not to_delete:
                        continue
                    confirm = input(f"⚠️ Confirm deletion of {len(to_delete)} folder(s)? Type 'yes' to proceed: ").strip()
                    if confirm.lower() == 'yes':
                        fids_to_delete = [fid for _, _, fid in to_delete]
                        MAX_BATCH = self.config.MOVE_MAX_FILE_IDS
                        deleted_indices = []
                        for i in range(0, len(fids_to_delete), MAX_BATCH):
                            batch_fids = fids_to_delete[i:i + MAX_BATCH]
                            success, error_msg = self.api_service.delete_files_or_folders(batch_fids)
                            if success:
                                logging.info(f"✅ Successfully deleted batch {i // MAX_BATCH + 1} ({len(batch_fids)} folders)")
                                deleted_indices.extend([item[0] for item in to_delete[i:i + MAX_BATCH]])
                            else:
                                logging.error(f"❌ Failed to delete batch {i // MAX_BATCH + 1}: {error_msg}")
                        # 从 display_list 中移除已删除项（从后往前删）
                        for idx in sorted(deleted_indices, reverse=True):
                            display_list.pop(idx)
                        if display_list:
                            # 重新分类显示（简化：只重新输出，不重新扫描）
                            logging.info("--- Remaining folders ---")
                            nonzero_remaining = [(p,s,f) for (p,s,f) in display_list if parse_human_readable_size(s) > 0]
                            zero_remaining = [(p,s,f) for (p,s,f) in display_list if parse_human_readable_size(s) == 0]
                            if nonzero_remaining:
                                logging.info(f"--- [Non-zero Folders] ({len(nonzero_remaining)} left) ---")
                                for i, (path, size, _) in enumerate(nonzero_remaining):
                                    logging.info(f"[{i}] {size:>10}  {path}")
                            if zero_remaining:
                                logging.info(f"--- [Zero-sized Folders] ({len(zero_remaining)} left) ---")
                                start_i = len(nonzero_remaining)
                                for j, (path, size, _) in enumerate(zero_remaining):
                                    logging.info(f"[{start_i + j}] {size:>10}  {path}")
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

        return CMD_RENDER_NEEDED # 或者 CMD_CONTINUE_INPUT，取决于是否需要刷新主界面

    def v(self, action_choice: str, page_items: List[Dict]) -> str:
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
        for original_idx, item_data in valid_selected_items_with_info:
            file_name = _get_item_attribute(item_data, "fn", "file_name", default_value="未知文件")
            try:
                download_url_candidate, _, _ = self.api_service.get_download_link_details(item_data)
                if download_url_candidate:
                    if self.config.DEFAULT_PLAYBACK_STRATEGY == 2 or file_name.lower().endswith('.iso'):
                        self._play_with_infuse(download_url_candidate, file_name)
                    else:
                        self._play_with_mpv(download_url_candidate, file_name)
            except Exception as exc:
                logging.error(f"获取 '{file_name}' 下载链接或播放时发生错误：{exc}")
        return CMD_RENDER_NEEDED
    def g(self, action_choice: str, *args) -> str:
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
    def p(self) -> str:
        if self.state.showing_all_items:
            logging.warning("Currently displaying all items, pagination not supported.")
            return CMD_CONTINUE_INPUT
        self.state.current_offset = max(0, self.state.current_offset - self.config.PAGINATOR_DISPLAY_SIZE)
        return CMD_RENDER_NEEDED
    def n(self) -> str:
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
    def t(self) -> str:
        self.config.show_list_short_form = not self.config.show_list_short_form
        mode_text = "Compact mode (name only)" if self.config.show_list_short_form else "Full mode (all details)"
        logging.info(f"Display mode toggled to: {mode_text}.")
        return CMD_RENDER_NEEDED
    def mc(self) -> str:
        self.config.enable_concurrent_c_details_fetching = not self.config.enable_concurrent_c_details_fetching
        status_text = "Enabled" if self.config.enable_concurrent_c_details_fetching else "Disabled"
        logging.info(f"Concurrent detail fetching for 'c' command is now {status_text}.")
        return CMD_CONTINUE_INPUT
    def f(self, action_choice: str, *args) -> str:
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
    def s(self) -> str:
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
        self.state.current_offset = 0
        self.state.showing_all_items = False
        self.state.title = f"Filtered list for directory '{_get_item_attribute(new_s_params, 'cid', default_value=self.config.ROOT_CID)}'"
        self.state._last_fetched_params_hash = None
        return CMD_RENDER_NEEDED
    def index_selection(self, action_choice: str, page_items_to_display: List[Dict]) -> str:
        selected_indices = parse_indices_input(action_choice, len(page_items_to_display))
        if selected_indices is None:
            logging.info("Operation cancelled.")
            return CMD_CONTINUE_INPUT
        if not selected_indices and action_choice.lower() in ['a', 'all'] and not page_items_to_display:
            logging.warning("Current list is empty, cannot perform 'a' / 'all' operation.")
            return CMD_CONTINUE_INPUT
        if not selected_indices and action_choice.lower() not in ['a', 'all']:
            return CMD_CONTINUE_INPUT
        if len(selected_indices) == 1 and is_item_folder(page_items_to_display[selected_indices[0]]):
            item_index = selected_indices[0]
            selected_item = page_items_to_display[item_index]
            target_cid = _get_item_attribute(selected_item, "fid", "file_id", default_value=self.config.ROOT_CID)
            folder_name = _get_item_attribute(selected_item, "fn", "file_name", default_value="Unknown Folder")
            self.state.parent_cid_stack.append(self.state.create_snapshot())
            self._navigate_to_cid(target_cid, title=f"Folder '{folder_name}' List")
            return CMD_RENDER_NEEDED
        else:
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

    def h(self):
        self.ui_renderer.display_help()
    def save(self, action_choice: str, page_items: List[Dict]) -> str:
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
            self._fetch_all_items_and_update_state()
            items_to_save = self.state._all_items_cache
        else:
            items_to_save = self.state.get_current_display_items()
            logging.info("Saving current page items to JSON file.")
        if self.config.enable_concurrent_c_details_fetching and items_to_save:
            enrich_items_with_details(items_to_save, self.api_service)
        save_json_output(items_to_save, output_filepath)
        return CMD_CONTINUE_INPUT
    def m(self, action_choice: str, page_items: List[Dict]) -> str:
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
                elif file_id and file_id in self.state.marked_for_move_file_ids:
                    logging.info(f"'{file_name}' (ID: {file_id}) is already in the marked list.")
            else:
                logging.warning(f"Index {index} is out of current page range.")
        return CMD_RENDER_NEEDED
    def mm(self) -> str:
        if not self.state.marked_for_move_file_ids:
            logging.warning("No marked files/folders to move. Please mark files using 'm <index>' first.")
            return CMD_CONTINUE_INPUT
        target_cid = self.state.current_folder_id
        if not target_cid:
            logging.error("Could not determine current directory CID. Cannot perform move operation.")
            return CMD_CONTINUE_INPUT
        confirm = input(f"Confirm moving {len(self.state.marked_for_move_file_ids)} file(s)/folder(s) to current directory (ID: {target_cid})? (y/n): ").strip().lower()
        if confirm == 'y':
            success = self.api_service.move_files(self.state.marked_for_move_file_ids, target_cid, file_count=len(self.state.marked_for_move_file_ids))
            if success:
                #_log_move_operation(self.state.marked_for_move_file_ids, target_cid, self.config)
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
    def merge(self) -> str:
        if not self.state.marked_for_move_file_ids:
            logging.warning("No marked files/folders to merge. Please mark files using 'm <index>' first.")
            return CMD_CONTINUE_INPUT

        target_cid = self.state.current_folder_id
        if not target_cid:
            logging.error("Could not determine current directory CID.")
            return CMD_CONTINUE_INPUT

        # 先过滤出 marked 中的 folder（merge 仅对 folder 有意义）
        current_page_items = self.state.get_current_display_items()
        source_folders = []
        for fid in self.state.marked_for_move_file_ids:
            # 从当前页或通过 API 补全 item
            item = next((it for it in current_page_items if _get_item_attribute(it, "fid", "file_id") == fid), None)
            if not item:
                details = self.api_service.get_item_details(fid)
                if details:
                    item = {
                        "fid": fid,
                        "fn": details.get("file_name", "Unknown"),
                        "fc": "0" if details.get("file_category") == "0" else "1"
                    }
                else:
                    logging.warning(f"Failed to retrieve info for marked item ID {fid}, skipping.")
                    continue
            if is_item_folder(item):
                source_folders.append(item)
            else:
                logging.info(f"Skipping non-folder marked item: '{_get_item_attribute(item, 'fn', 'file_name', default_value='Unknown')}'")

        if not source_folders:
            logging.warning("No folders among marked items. 'merge' only applies to folders.")
            return CMD_CONTINUE_INPUT

        # ——— 逐 folder 处理 ———
        total_success = 0
        total_fail = 0
        skipped_empty = 0

        for idx, src_folder in enumerate(source_folders, 1):
            src_fid = _get_item_attribute(src_folder, "fid", "file_id")
            src_name = _get_item_attribute(src_folder, "fn", "file_name", default_value="Unknown")
            logging.info(f"\n[📁 Merge {idx}/{len(source_folders)}] Processing folder: '{src_name}' (ID: {src_fid})")
            existing_target_items = {}
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
                logging.info(f"  → Folder '{src_name}' is empty, skipped.")
                skipped_empty += 1
                continue

            # Step 3: 构建本 folder 的 move plan
            move_plan = []  # [(fid, target_cid), ...]
            for sub_item in sub_items:
                sub_fid = _get_item_attribute(sub_item, "fid", "file_id")
                sub_name = _get_item_attribute(sub_item, "fn", "file_name", default_value="Unknown")
                sub_is_folder = is_item_folder(sub_item)
                if not sub_fid or not sub_name:
                    continue

                if not sub_is_folder:
                    move_plan.append((sub_fid, target_cid))
                else:
                    sub_name_lower = sub_name.lower()
                    if sub_name_lower in existing_target_items:
                        existing_fid, existing_is_folder = existing_target_items[sub_name_lower]
                        if existing_is_folder:
                            gc_offset = 0
                            while True:
                                gc_page, _ = self.api_service.fetch_files_in_directory_page(
                                    cid=sub_fid, limit=self.config.API_FETCH_LIMIT, offset=gc_offset, show_dir="1"
                                )
                                if not gc_page:
                                    break
                                for gc in gc_page:
                                    gc_fid = _get_item_attribute(gc, "fid", "file_id")
                                    if gc_fid:
                                        move_plan.append((gc_fid, existing_fid))
                                gc_offset += len(gc_page)
                        else:
                            move_plan.append((sub_fid, target_cid))
                    else:
                        move_plan.append((sub_fid, target_cid))

            if not move_plan:
                logging.info(f"  → No items to move for '{src_name}', skipped.")
                continue
            logging.info(f"  → Moving {len(move_plan)} items from '{src_name}'...")
            groups = {}
            for fid, tgt_cid in move_plan:
                groups.setdefault(tgt_cid, []).append(fid)

            folder_success = 0
            folder_fail = 0
            MAX_MOVE = self.config.MOVE_MAX_FILE_IDS

            for tgt_cid, fids in groups.items():
                for i in range(0, len(fids), MAX_MOVE):
                    batch = fids[i:i + MAX_MOVE]
                    if self.api_service.move_files(batch, tgt_cid, file_count=len(batch)):
                        folder_success += len(batch)
                    else:
                        folder_fail += len(batch)
            #_log_move_operation([src_fid], target_cid, self.config)
            if folder_fail == 0:
                logging.info(f"✅ [{idx}/{len(source_folders)}] Merge completed for '{src_name}' ({folder_success} items moved).")
                total_success += 1
            else:
                logging.warning(f"⚠️ [{idx}/{len(source_folders)}] Merge partially failed for '{src_name}' ({folder_success} success / {folder_fail} failed).")
                total_fail += 1
            self.state._last_fetched_params_hash = None
        summary = f"✨ Merge Summary: {len(source_folders)} folders processed"
        if total_success:
            summary += f" | ✅ Success: {total_success}"
        if total_fail:
            summary += f" | ⚠️ Partial/Failed: {total_fail}"
        if skipped_empty:
            summary += f" | 🚫 Empty Skipped: {skipped_empty}"
        logging.info(summary)

        self.state.marked_for_move_file_ids = []
        self.state.current_offset = 0
        return CMD_RENDER_NEEDED

    def up(self, action_choice: str, page_items: List[Dict]) -> str:
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
                self._navigate_to_cid(target_cid, title=f"Folder '{target_name}' List")
                logging.info(f"Entered directory: '{target_name}' (CID: {target_cid})")
                return CMD_RENDER_NEEDED
            else:
                logging.warning(f"Index {choice_idx} out of range.")
                return CMD_CONTINUE_INPUT
        except ValueError:
            logging.warning("Invalid input. Please enter a number.")
            return CMD_CONTINUE_INPUT
    def add(self, action_choice: str, page_items: List[Dict]) -> str:
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
    def rename(self, action_choice: str, page_items: List[Dict]) -> str:
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
    def del_(self, action_choice: str, page_items_to_display: List[Dict]) -> str:
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
            # === 自动分批删除 ===
            MAX_BATCH = self.config.MOVE_MAX_FILE_IDS
            all_success = True
            for i in range(0, len(file_ids_to_delete), MAX_BATCH):
                batch = file_ids_to_delete[i:i + MAX_BATCH]
                success, error_message = self.api_service.delete_files_or_folders(batch, self.state.current_folder_id)
                if not success:
                    logging.error(f"Delete batch {i // MAX_BATCH + 1} failed: {error_message}")
                    all_success = False
            if all_success:
                logging.info("All delete batches completed successfully.")
                self.state._last_fetched_params_hash = None
                self.state.current_offset = 0
                return CMD_RENDER_NEEDED
            else:
                logging.error("Some delete batches failed. Please check logs.")
                return CMD_CONTINUE_INPUT
        else:
            logging.info("Delete operation cancelled.")
            return CMD_CONTINUE_INPUT
    def cloud(self) -> str:
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
            force_full = self.state._force_full_display_next_render
            self.state._force_full_display_next_render = False
            self.ui_renderer.display_paginated_items_list(page_items_to_display, force_full_display=force_full)
            if self.state.marked_for_move_file_ids:
                logging.info(f"Marked {len(self.state.marked_for_move_file_ids)} items for move.")
            while True:
                action_choice = input(f"分页 {self.state.current_display_page}/{self.state.total_display_pages}, 命令: ").strip().lower()
                logging.info("------")
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
# ==================== 全局函数（保持不变）====================
def parse_human_readable_size(size_str: str) -> int:
    if not isinstance(size_str, str):
        return 0
    size_str = size_str.strip()
    if size_str == "0 B" or size_str == "0B" or size_str == "0":
        return 0
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
    if input_str_lower in ('a', 'all'):
        return list(range(total_items))
    selected_indices = set()
    for part in input_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if start <= end:
                    selected_indices.update(i for i in range(start, end + 1) if 0 <= i < total_items)
                else:
                    logging.warning(f"Invalid range '{part}', start > end. Ignored.")
            except ValueError:
                logging.warning(f"Range '{part}' invalid format. Use 'start-end'. Ignored.")
        else:
            try:
                idx = int(part)
                if 0 <= idx < total_items:
                    selected_indices.add(idx)
                else:
                    logging.warning(f"Index {idx} out of range (0-{total_items - 1}). Ignored.")
            except ValueError:
                logging.warning(f"Invalid index: '{part}'. Ignored.")
    return sorted(selected_indices)
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
# =============== 主函数（新增 jump 命令支持） ===============
def main():
    config = AppConfig()
    raw_args = sys.argv[1:]
    if not raw_args:
        # 创建单个 ApiService 实例
        api_service = ApiService(config)
        initial_browse_params = config.PREDEFINED_FETCH_PARAMS["default_browse"]["params"].copy()
        first_api_chunk_items, total_count = api_service.fetch_files_in_directory_page(
            cid=config.ROOT_CID, limit=config.API_FETCH_LIMIT, offset=0, **initial_browse_params
        )
        if total_count == 0:
            logging.info("No files or folders found in the root directory, script terminated.")
            sys.exit(0)
        # 将 ApiService 实例传入 FileBrowser
        browser = FileBrowser(
            initial_cid=config.ROOT_CID,
            initial_browse_params=initial_browse_params,
            initial_api_chunk=first_api_chunk_items,
            total_items=total_count,
            config=config,
            api_service=api_service  # 传入已创建的实例
        )
        exit_signal = browser.run_browser()
        if exit_signal == CMD_EXIT:
            logging.info("\n--- Script exited successfully ---")
        else:
            logging.info("\n--- Script execution completed ---")
        return
    command_chain_str = ' '.join(raw_args)
    subcommand_strings = [part.strip() for part in command_chain_str.split('=') if part.strip()]
    if not subcommand_strings:
        logging.error("No valid commands after splitting by '='.")
        sys.exit(1)
    api_service = ApiService(config)
    browser = FileBrowser(
        initial_cid=config.ROOT_CID,
        initial_browse_params=config.PREDEFINED_FETCH_PARAMS["default_browse"]["params"].copy(),
        initial_api_chunk=[],
        total_items=0,
        config=config,
        api_service=api_service  # 传入已创建的实例
    )
    for cmd_str in subcommand_strings:
        cmd_parts = shlex.split(cmd_str)
        if not cmd_parts:
            continue
        cmd = cmd_parts[0]
        sub_args = cmd_parts[1:]
        if cmd == 'q':
            logging.info("\n--- Script exited by 'q' command ---")
            return
        browser._refresh_paginator_data()
        current_page_items = browser.state.get_current_display_items()
        if cmd == 'jump':
            predefined_list = get_predefined_folder_list(config.PREDEFINED_SAVE_FOLDERS)
            if not sub_args:
                logging.error("jump 命令在命令行模式下必须指定索引")
                sys.exit(1)
            try:
                idx = int(sub_args[0])
                if 0 <= idx < len(predefined_list):
                    _, target_cid = predefined_list[idx]
                    browser._navigate_to_cid(target_cid)
                else:
                    logging.error(f"jump index {idx} out of range (0–{len(predefined_list)-1})")
                    sys.exit(1)
            except ValueError:
                logging.error("jump index must be an integer")
                sys.exit(1)
            continue
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
                folder_name = _get_item_attribute(selected_item, "fn", "file_name", default_value="Unknown Folder")
                target_cid = _get_item_attribute(selected_item, "fid", "file_id", default_value=config.ROOT_CID)
                browser.state.parent_cid_stack.append(browser.state.create_snapshot())
                browser._navigate_to_cid(target_cid, title=f"Folder '{folder_name}' List")
            else:
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
        # ... 其他命令逻辑保持不变 ...
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
            browser.command_processor.process_command(f"v {' '.join(sub_args)}", current_page_items)
            continue
        elif cmd == 'd':
            indices = _get_indices_from_args(sub_args, len(current_page_items))
            if not indices:
                logging.error("No valid index for 'd'")
                sys.exit(1)
            browser.command_processor.process_command(f"d {' '.join(sub_args)}", current_page_items)
            continue
        elif cmd == 'i':
            indices = _get_indices_from_args(sub_args, len(current_page_items))
            if not indices:
                logging.error("No valid index for 'i'")
                sys.exit(1)
            browser.command_processor.process_command(f"i {' '.join(sub_args)}", current_page_items)
            continue
        elif cmd == 'a':
            browser._fetch_all_items_and_update_state()
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
            target_cid = resolve_target_cid(target_spec, config.PREDEFINED_UPLOAD_FOLDERS)
            upload_manager = UploadManager(config, api_service)
            results = upload_manager.upload_paths_to_target([local_path], target_cid)
            for success, msg in results:
                (logging.info if success else logging.error)(f"{'✅' if success else '❌'} {msg}")
            continue
        elif cmd == 'cloud':
            if len(sub_args) < 1:
                logging.error("Usage: cloud <urls> [target]")
                sys.exit(1)
            urls = sub_args[0]
            target_spec = sub_args[1] if len(sub_args) >= 2 else None
            target_cid = resolve_target_cid(target_spec, config.PREDEFINED_SAVE_FOLDERS)
            success, msg, _ = api_service.add_cloud_download_task(urls, target_cid)
            (logging.info if success else logging.error)(f"{'✅' if success else '❌'} {msg}")
            continue
        elif cmd == 'n':
            if not browser.state.showing_all_items:
                browser.n()
            continue
        elif cmd == 'p':
            if not browser.state.showing_all_items:
                browser.p()
            continue
        elif cmd == 'g' and len(sub_args) == 1:
            try:
                page_num = int(sub_args[0])
                browser.g(f"g {page_num}")
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
            browser._navigate_to_cid(target_cid)
            continue
        else:
            logging.error(f"Unknown command: '{cmd}'")
            sys.exit(1)
    logging.info("\n--- Entering interactive mode ---")
    exit_signal = browser.run_browser()
    if exit_signal == CMD_EXIT:
        logging.info("\n--- Script exited successfully ---")
    else:
        logging.info("\n--- Script execution completed ---")
if __name__ == "__main__":
    main()
