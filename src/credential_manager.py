"""
High-performance credential manager with call-based rotation and caching.
Rotates credentials based on API call count rather than time for better quota distribution.
"""
import os
import json
import asyncio
import glob
import aiofiles
import toml
import base64
import time
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
import httpx

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest

from config import (
    CREDENTIALS_DIR, CODE_ASSIST_ENDPOINT,
    get_proxy_config, get_calls_per_rotation, get_http_timeout, get_max_connections,
    get_auto_ban_enabled,
    get_auto_ban_error_codes
)
from .utils import get_user_agent, get_client_metadata
from log import log

def _normalize_to_relative_path(filepath: str, base_dir: str = None) -> str:
    """将文件路径标准化为相对于CREDENTIALS_DIR的相对路径"""
    if base_dir is None:
        from config import CREDENTIALS_DIR
        base_dir = CREDENTIALS_DIR
    
    # 如果已经是相对路径且在当前目录内，直接返回
    if not os.path.isabs(filepath):
        # 检查相对路径是否安全（不包含..等）
        if ".." not in filepath and filepath.endswith('.json'):
            return os.path.basename(filepath)  # 只保留文件名
    
    # 绝对路径转相对路径
    abs_filepath = os.path.abspath(filepath)
    abs_base_dir = os.path.abspath(base_dir)
    
    try:
        # 如果文件在base_dir内，返回相对路径（只要文件名）
        if abs_filepath.startswith(abs_base_dir):
            return os.path.basename(abs_filepath)
    except Exception:
        pass
    
    # 环境变量路径保持原样
    if filepath.startswith('<ENV_'):
        return filepath
    
    # 其他情况也只返回文件名
    return os.path.basename(filepath)

def _relative_to_absolute_path(relative_path: str, base_dir: str = None) -> str:
    """将相对路径转换为绝对路径"""
    if base_dir is None:
        from config import CREDENTIALS_DIR
        base_dir = CREDENTIALS_DIR
    
    # 环境变量路径保持原样
    if relative_path.startswith('<ENV_'):
        return relative_path
    
    # 如果已经是绝对路径，直接返回
    if os.path.isabs(relative_path):
        return relative_path
    
    # 相对路径转绝对路径
    return os.path.abspath(os.path.join(base_dir, relative_path))

class CredentialManager:
    """High-performance credential manager with call-based rotation and caching."""

    def __init__(self, calls_per_rotation: int = None):  # Use dynamic config by default
        self._lock = asyncio.Lock()
        self._current_credential_index = 0
        self._credential_files: List[str] = []
        
        # Call-based rotation instead of time-based
        self._cached_credentials: Optional[Credentials] = None
        self._cached_project_id: Optional[str] = None
        self._call_count = 0
        self._calls_per_rotation = calls_per_rotation or get_calls_per_rotation()
        
        # Onboarding state
        self._onboarding_complete = False
        self._onboarding_checked = False
        
        # HTTP client reuse
        self._http_client: Optional[httpx.AsyncClient] = None
        
        # TOML状态文件路径
        self._state_file = os.path.join(CREDENTIALS_DIR, "creds_state.toml")
        self._creds_state: Dict[str, Any] = {}
        
        # 当前使用的凭证文件路径
        self._current_file_path: Optional[str] = None
        
        self._initialized = False

    async def initialize(self):
        """Initialize the credential manager."""
        async with self._lock:
            if self._initialized:
                return
            
            # 加载状态文件
            await self._load_state()
            
            await self._discover_credential_files()
            
            # Initialize HTTP client with connection pooling and proxy support
            proxy = get_proxy_config()
            client_kwargs = {
                "timeout": get_http_timeout(),
                "limits": httpx.Limits(max_keepalive_connections=20, max_connections=get_max_connections())
            }
            if proxy:
                client_kwargs["proxy"] = proxy
            self._http_client = httpx.AsyncClient(**client_kwargs)
            
            self._initialized = True

    async def close(self):
        """Clean up resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def _load_state(self):
        """从TOML文件加载状态"""
        try:
            if os.path.exists(self._state_file):
                async with aiofiles.open(self._state_file, "r", encoding="utf-8") as f:
                    content = await f.read()
                self._creds_state = toml.loads(content)
            else:
                self._creds_state = {}
            
        except Exception as e:
            log.warning(f"Failed to load state file: {e}")
            self._creds_state = {}

    async def _save_state(self):
        """保存状态到TOML文件"""
        try:
            os.makedirs(os.path.dirname(self._state_file), exist_ok=True)
            async with aiofiles.open(self._state_file, "w", encoding="utf-8") as f:
                await f.write(toml.dumps(self._creds_state))
        except Exception as e:
            log.error(f"Failed to save state file: {e}")


    
    def _get_cred_state(self, filename: str) -> Dict[str, Any]:
        """获取指定凭证文件的状态，使用相对路径作为键"""
        # 标准化为相对路径
        relative_filename = _normalize_to_relative_path(filename)
        
        # 先检查是否已存在（支持向后兼容）
        existing_state = None
        existing_key = None
        
        # 优先查找相对路径键
        if relative_filename in self._creds_state:
            return self._creds_state[relative_filename]
        
        # 向后兼容：查找可能的绝对路径键并迁移
        for key, state in list(self._creds_state.items()):
            if os.path.isabs(key):
                # 检查绝对路径是否对应同一个文件
                if _normalize_to_relative_path(key) == relative_filename:
                    existing_state = state
                    existing_key = key
                    break
            elif key == relative_filename:
                # 理论上不会到这里，但为安全起见
                return state
        
        if existing_state is not None:
            # 迁移绝对路径键到相对路径键
            self._creds_state[relative_filename] = existing_state
            del self._creds_state[existing_key]
            log.info(f"Migrated creds state key from absolute to relative: {existing_key} -> {relative_filename}")
            return existing_state
        
        # 创建新状态（使用相对路径作为键）
        log.debug(f"Creating new state for {relative_filename}")
        self._creds_state[relative_filename] = {
            "error_codes": [],
            "disabled": False,
            "last_success": None,
            "user_email": None
        }
        return self._creds_state[relative_filename]

    async def record_error(self, filename: str, status_code: int, response_content: str = ""):
        """记录API错误码"""
        async with self._lock:
            # 使用相对路径进行状态管理
            relative_filename = _normalize_to_relative_path(filename)
            cred_state = self._get_cred_state(filename)
            
            # 记录错误码
            if "error_codes" not in cred_state:
                cred_state["error_codes"] = []
            if status_code not in cred_state["error_codes"]:
                cred_state["error_codes"].append(status_code)
            
            # 简单记录429错误，不做特殊处理
            if status_code == 429:
                log.info(f"Got 429 error for {os.path.basename(filename)}")
            
            # 自动封禁功能
            auto_ban_enabled = get_auto_ban_enabled()
            auto_ban_error_codes = get_auto_ban_error_codes()
            log.debug(f"AUTO_BAN check: enabled={auto_ban_enabled}, status_code={status_code}, error_codes={auto_ban_error_codes}")
            if auto_ban_enabled and status_code in auto_ban_error_codes:
                if not cred_state.get("disabled", False):
                    cred_state["disabled"] = True
                    log.warning(f"AUTO_BAN: Disabled credential {os.path.basename(filename)} due to error {status_code}")
                else:
                    log.debug(f"Credential {os.path.basename(filename)} already disabled, error {status_code} recorded")
            elif auto_ban_enabled:
                log.debug(f"AUTO_BAN enabled but status_code {status_code} not in ban list {auto_ban_error_codes}")
            else:
                log.debug(f"AUTO_BAN disabled, status_code {status_code} recorded but no auto ban")
            
            await self._save_state()

    async def record_success(self, filename: str, api_type: str = "other"):
        """记录成功的API调用"""
        async with self._lock:
            # 使用相对路径进行状态管理
            cred_state = self._get_cred_state(filename)
            
            # 只有聊天内容生成API成功才清除错误码，其他API不清除
            if api_type == "chat_content":
                cred_state["error_codes"] = []
                log.debug(f"Cleared error codes for {filename} due to successful chat content generation")
            
            cred_state["last_success"] = datetime.now(timezone.utc).isoformat()
            
            await self._save_state()

    async def fetch_user_email(self, filename: str) -> Optional[str]:
        """获取凭证对应的用户邮箱地址"""
        try:
            # 加载凭证
            creds, _ = await self._load_credentials_from_file(filename)
            if not creds or not creds.token:
                log.warning(f"无法加载凭证或获取访问令牌: {filename}")
                return None
            
            # 刷新令牌如果需要
            if creds.expired and creds.refresh_token:
                try:
                    creds.refresh(GoogleAuthRequest())
                except Exception as e:
                    log.warning(f"刷新凭证失败 {filename}: {e}")
                    return None
            
            # 调用Google userinfo API获取邮箱
            if not self._http_client:
                log.warning("HTTP客户端未初始化")
                return None
                
            headers = {
                "Authorization": f"Bearer {creds.token}",
                "Accept": "application/json"
            }
            
            response = await self._http_client.get(
                "https://openidconnect.googleapis.com/v1/userinfo",
                headers=headers
            )
            
            if response.status_code == 200:
                user_info = response.json()
                email = user_info.get("email")
                if email:
                    log.info(f"成功获取邮箱地址: {email} for {os.path.basename(filename)}")
                    return email
                else:
                    log.warning(f"userinfo响应中没有邮箱信息: {user_info}")
                    return None
            else:
                log.warning(f"获取用户信息失败 {filename}: HTTP {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            log.error(f"获取用户邮箱失败 {filename}: {e}")
            return None

    async def get_or_fetch_user_email(self, filename: str) -> Optional[str]:
        """获取用户邮箱（优先使用缓存，如果没有则从API获取）"""
        async with self._lock:
            cred_state = self._get_cred_state(filename)
            
            # 检查是否已经有邮箱信息
            if "user_email" in cred_state and cred_state["user_email"]:
                return cred_state["user_email"]
        
        # 从API获取邮箱
        email = await self.fetch_user_email(filename)
        if email:
            async with self._lock:
                cred_state = self._get_cred_state(filename)
                cred_state["user_email"] = email
                await self._save_state()
        
        return email


    def is_cred_disabled(self, filename: str) -> bool:
        """检查凭证是否被禁用"""
        cred_state = self._get_cred_state(filename)
        return cred_state.get("disabled", False)

    async def set_cred_disabled(self, filename: str, disabled: bool):
        """设置凭证的禁用状态"""
        async with self._lock:
            relative_filename = _normalize_to_relative_path(filename)
            log.info(f"Setting disabled={disabled} for file: {relative_filename}")
            cred_state = self._get_cred_state(filename)
            old_disabled = cred_state.get("disabled", False)
            cred_state["disabled"] = disabled
            log.info(f"Updated state for {relative_filename}: {cred_state}")
            await self._save_state()
            log.info(f"State saved successfully")
            
            # 如果状态发生了变化，强制重新发现文件并清空缓存
            if old_disabled != disabled:
                log.info(f"Credential disabled status changed from {old_disabled} to {disabled}, refreshing file list")
                # 清空缓存，强制下次获取凭证时重新加载
                self._cached_credentials = None
                self._cached_project_id = None
                self._cache_timestamp = 0
                
                # 立即重新发现文件以更新可用文件列表
                await self._discover_credential_files()
                log.info(f"File list refreshed. Available files: {len(self._credential_files)}")

    def get_creds_status(self) -> Dict[str, Dict[str, Any]]:
        """获取所有凭证的状态信息"""
        status = {}
        # 获取所有文件
        credentials_dir = CREDENTIALS_DIR
        patterns = [os.path.join(credentials_dir, "*.json")]
        all_files = []
        for pattern in patterns:
            all_files.extend(glob.glob(pattern))
        all_files = sorted(list(set(all_files)))
        
        for filename in all_files:
            # 使用相对路径作为键，但返回时仍使用绝对路径（兼容前端）
            absolute_filename = os.path.abspath(filename)
            cred_state = self._get_cred_state(filename)
            file_status = {
                "error_codes": cred_state.get("error_codes", []),
                "disabled": cred_state.get("disabled", False),
                "last_success": cred_state.get("last_success"),
                "user_email": cred_state.get("user_email")
            }
            status[absolute_filename] = file_status
            
            # 调试：记录特定文件的状态
            basename = os.path.basename(filename)
            if "atomic-affinity" in basename:
                relative_filename = _normalize_to_relative_path(filename)
                log.info(f"Status for {basename}: disabled={file_status['disabled']} (normalized: {relative_filename})")
                
        return status

    def get_current_file_path(self) -> Optional[str]:
        """获取当前使用的凭证文件路径"""
        return self._current_file_path

    async def _discover_credential_files(self):
        """Discover all credential files with hot reload support."""
        old_files = set(self._credential_files)
        all_files = []
        
        # First, check environment variables for credentials
        env_creds_loaded = False
        for i in range(1, 11):  # Support up to 10 credentials from env vars
            env_var_name = f"GOOGLE_CREDENTIALS_{i}" if i > 1 else "GOOGLE_CREDENTIALS"
            env_creds = os.getenv(env_var_name)
            
            if env_creds:
                try:
                    # Try to decode if it's base64 encoded
                    try:
                        # Check if it's base64 encoded
                        decoded = base64.b64decode(env_creds)
                        env_creds = decoded.decode('utf-8')
                        log.debug(f"Decoded base64 credential from {env_var_name}")
                    except:
                        # Not base64, use as is
                        pass
                    
                    # Parse the JSON credential from environment variable
                    cred_data = json.loads(env_creds)
                    
                    # Auto-add 'type' field if missing but has required OAuth fields
                    if 'type' not in cred_data and all(key in cred_data for key in ['client_id', 'refresh_token']):
                        cred_data['type'] = 'authorized_user'
                        log.debug(f"Auto-added 'type' field to credential from {env_var_name}")
                    
                    if all(key in cred_data for key in ['type', 'client_id', 'refresh_token']):
                        # Save to a temporary file for compatibility with existing code
                        temp_file = os.path.join(CREDENTIALS_DIR, f"env_credential_{i}.json")
                        os.makedirs(CREDENTIALS_DIR, exist_ok=True)
                        with open(temp_file, 'w') as f:
                            json.dump(cred_data, f)
                        all_files.append(temp_file)
                        log.info(f"Loaded credential from environment variable: {env_var_name}")
                        env_creds_loaded = True
                    else:
                        log.warning(f"Invalid credential format in {env_var_name}")
                except json.JSONDecodeError as e:
                    log.warning(f"Failed to parse JSON from {env_var_name}: {e}")
                except Exception as e:
                    log.warning(f"Error loading credential from {env_var_name}: {e}")
        
        # If no env credentials, discover from directory
        if not env_creds_loaded:
            credentials_dir = CREDENTIALS_DIR
            patterns = [os.path.join(credentials_dir, "*.json")]
            
            for pattern in patterns:
                discovered_files = glob.glob(pattern)
                # Skip env_credential files if loading from directory
                for file in discovered_files:
                    if not os.path.basename(file).startswith("env_credential_"):
                        all_files.append(file)
        
        all_files = sorted(list(set(all_files)))
        
        # 过滤掉被禁用的文件（移除CD机制）
        self._credential_files = []
        for filename in all_files:
            is_disabled = self.is_cred_disabled(filename)
            
            if not is_disabled:
                self._credential_files.append(filename)
            else:
                # 记录被过滤的文件信息供调试
                log.debug(f"Filtered out {os.path.basename(filename)}: disabled")
        
        new_files = set(self._credential_files)
        
        # 检测文件变化
        if old_files != new_files:
            added_files = new_files - old_files
            removed_files = old_files - new_files
            
            if added_files:
                log.info(f"发现新的可用凭证文件: {list(added_files)}")
                # 清除缓存以便使用新文件
                self._cached_credentials = None
                self._cached_project_id = None
            
            if removed_files:
                log.info(f"凭证文件已移除或不可用: {list(removed_files)}")
                # 如果当前使用的文件被移除，切换到下一个文件
                if self._credential_files and self._current_credential_index >= len(self._credential_files):
                    self._current_credential_index = 0
                    self._cached_credentials = None
                    self._cached_project_id = None
        
        # 同步状态文件，清理不存在的文件状态
        await self._sync_state_with_files(all_files)
        
        if not self._credential_files:
            log.warning("No available credential files found")
        else:
            available_files = [os.path.basename(f) for f in self._credential_files]
            log.info(f"Found {len(self._credential_files)} available credential files: {available_files}")

    async def _sync_state_with_files(self, current_files: List[str]):
        """同步状态文件与实际文件"""
        # 标准化当前文件列表为相对路径
        normalized_current_files = [_normalize_to_relative_path(f) for f in current_files]
        
        # 移除不存在文件的状态
        files_to_remove = []
        for filename in list(self._creds_state.keys()):
            # 将状态文件中的键也标准化为相对路径进行比较
            normalized_state_key = _normalize_to_relative_path(filename) if not filename.startswith('<ENV_') else filename
            if normalized_state_key not in normalized_current_files:
                files_to_remove.append(filename)
        
        if files_to_remove:
            for filename in files_to_remove:
                del self._creds_state[filename]
            await self._save_state()
            log.info(f"Removed state for deleted files: {files_to_remove}")

    def _is_cache_valid(self) -> bool:
        """Check if cached credentials are still valid based on call count and token expiration."""
        if not self._cached_credentials:
            return False
        
        # 如果没有凭证文件，缓存无效
        if not self._credential_files:
            return False
        
        # Check if we've reached the rotation threshold (use dynamic config)
        current_calls_per_rotation = get_calls_per_rotation()
        if self._call_count >= current_calls_per_rotation:
            return False
        
        # Check token expiration (with 60 second buffer)
        if self._cached_credentials.expired:
            return False
        
        return True

    async def _rotate_credential_if_needed(self):
        """Rotate to next credential if call limit reached."""
        current_calls_per_rotation = get_calls_per_rotation()
        if self._call_count >= current_calls_per_rotation:
            self._current_credential_index = (self._current_credential_index + 1) % len(self._credential_files)
            self._call_count = 0  # Reset call counter
            log.info(f"Rotated to credential index {self._current_credential_index}")
    
    async def _force_rotate_credential(self):
        """Force rotate to next credential immediately (used for 429 errors)."""
        if len(self._credential_files) <= 1:
            log.warning("Only one credential available, cannot rotate")
            return
        
        old_index = self._current_credential_index
        self._current_credential_index = (self._current_credential_index + 1) % len(self._credential_files)
        self._call_count = 0  # Reset call counter
        log.info(f"Force rotated from credential index {old_index} to {self._current_credential_index} due to 429 error")

    async def _discover_credential_files_unlocked(self):
        """在锁外进行文件发现操作（用于避免阻塞其他操作）"""
        # 这个方法不使用锁，因为主要是文件系统读操作
        # 文件列表的更新会在后续的 _discover_credential_files 中同步
        
        # 临时存储发现的文件
        temp_files = []
        
        # 复制当前状态以避免并发修改问题
        try:
            from config import CREDENTIALS_DIR
            import glob
            
            # 检查环境变量凭证（与 _discover_credential_files 保持一致）
            for i in range(1, 11):
                env_var_name = f"GOOGLE_CREDENTIALS_{i}" if i > 1 else "GOOGLE_CREDENTIALS"
                env_creds = os.getenv(env_var_name)
                
                if env_creds:
                    try:
                        # 检查是否为base64编码
                        try:
                            import base64
                            decoded = base64.b64decode(env_creds)
                            env_creds = decoded.decode('utf-8')
                        except:
                            pass
                        
                        # 验证JSON格式
                        import json
                        json.loads(env_creds)
                        
                        # 创建临时文件路径标识
                        temp_env_path = f"<ENV_{env_var_name}>"
                        if not self.is_cred_disabled(temp_env_path):
                            temp_files.append(temp_env_path)
                        
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        log.error(f"Invalid JSON in {env_var_name}: {e}")
            
            # 检查文件系统中的凭证
            if os.path.exists(CREDENTIALS_DIR):
                json_pattern = os.path.join(CREDENTIALS_DIR, "*.json")
                for filepath in glob.glob(json_pattern):
                    # 检查禁用状态（内部使用相对路径），但文件列表保持绝对路径（供文件I/O使用）
                    if not self.is_cred_disabled(filepath):
                        temp_files.append(os.path.abspath(filepath))
            
            # 在锁内快速更新文件列表
            async with self._lock:
                if temp_files != self._credential_files:
                    old_files = set(self._credential_files)
                    self._credential_files = temp_files
                    new_files = set(self._credential_files)
                    
                    # 日志记录变化
                    if old_files != new_files:
                        added_files = new_files - old_files
                        removed_files = old_files - new_files
                        
                        if added_files:
                            log.info(f"发现新的可用凭证文件: {list(added_files)}")
                            # 清除缓存以便使用新文件
                            self._cached_credentials = None
                            self._cached_project_id = None
                            self._cache_timestamp = 0
                        
                        if removed_files:
                            log.info(f"移除不可用凭证文件: {list(removed_files)}")
        
        except Exception as e:
            log.error(f"Error in _discover_credential_files_unlocked: {e}")
            # 发生错误时，回退到带锁的方法
            async with self._lock:
                await self._discover_credential_files()

    async def _load_credential_with_fallback(self, current_file: str) -> Tuple[Optional[Credentials], Optional[str]]:
        """Load credentials with fallback to next file on failure."""
        creds, project_id = await self._load_credentials_from_file(current_file)
        if not creds:
            # Try next file on failure
            self._current_credential_index = (self._current_credential_index + 1) % len(self._credential_files)
            if self._current_credential_index < len(self._credential_files):
                current_file = self._credential_files[self._current_credential_index]
                creds, project_id = await self._load_credentials_from_file(current_file)
        return creds, project_id

    async def get_credentials(self) -> Tuple[Optional[Credentials], Optional[str]]:
        """Get credentials with call-based rotation, caching and hot reload for performance."""
        # 第一阶段：快速检查缓存（减少锁持有时间）
        async with self._lock:
            current_calls_per_rotation = get_calls_per_rotation()
            
            # 检查是否可以使用缓存，并验证当前文件是否仍然可用
            if self._is_cache_valid() and self._credential_files:
                # 额外检查：确保当前使用的文件没有被禁用
                current_file_still_valid = (
                    self._current_file_path and 
                    not self.is_cred_disabled(self._current_file_path) and
                    self._current_file_path in self._credential_files
                )
                
                if current_file_still_valid:
                    log.debug(f"Using cached credentials (call count: {self._call_count}/{current_calls_per_rotation})")
                    return self._cached_credentials, self._cached_project_id
                else:
                    log.info(f"Current credential file {self._current_file_path} is no longer valid, clearing cache")
                    self._cached_credentials = None
                    self._cached_project_id = None
                    self._cache_timestamp = 0
            
            # 检查是否需要重新发现文件
            should_check_files = (
                not self._credential_files or  # 无文件时每次都检查
                self._call_count >= current_calls_per_rotation  # 轮换时检查
            )
        
        # 第二阶段：如果需要，在锁外进行文件发现（避免阻塞其他操作）
        if should_check_files:
            # 文件发现操作不需要锁，因为它主要是读操作
            await self._discover_credential_files_unlocked()
        
        # 第三阶段：获取凭证（持有锁但时间较短）
        async with self._lock:
            current_calls_per_rotation = get_calls_per_rotation()  # 重新获取配置
            
            # 再次检查缓存（可能在文件发现过程中被其他操作更新）
            if self._is_cache_valid() and self._credential_files:
                # 验证当前文件是否仍然可用
                current_file_still_valid = (
                    self._current_file_path and 
                    not self.is_cred_disabled(self._current_file_path) and
                    self._current_file_path in self._credential_files
                )
                
                if current_file_still_valid:
                    log.debug(f"Using cached credentials after file discovery")
                    return self._cached_credentials, self._cached_project_id
                else:
                    log.info(f"Current credential file {self._current_file_path} is no longer valid after file discovery, forcing reload")
            
            # 需要加载新凭证
            if self._call_count >= current_calls_per_rotation:
                log.info(f"Rotating credentials after {self._call_count} calls")
            else:
                log.info("Cache miss - loading fresh credentials")
            
            # 轮换凭证
            await self._rotate_credential_if_needed()
            
            if not self._credential_files:
                log.error("No available credential files")
                return None, None
            
            current_file = self._credential_files[self._current_credential_index]
            
            # 记录当前使用的文件路径
            self._current_file_path = current_file
            
        # 第四阶段：在锁外加载凭证文件（避免I/O阻塞其他操作）
        creds, project_id = await self._load_credential_with_fallback(current_file)
        
        # 第五阶段：更新缓存（短时间持有锁）
        async with self._lock:
            if creds:
                self._cached_credentials = creds
                self._cached_project_id = project_id
                self._cache_timestamp = time.time()
                log.debug(f"Loaded and cached credentials from {os.path.basename(current_file)}")
            else:
                log.error(f"Failed to load credentials from {current_file}")
            
            return creds, project_id

    async def _load_credentials_from_file(self, file_path: str) -> Tuple[Optional[Credentials], Optional[str]]:
        """Load credentials from file (optimized)."""
        try:
            async with aiofiles.open(file_path, "r") as f:
                content = await f.read()
            creds_data = json.loads(content)
            
            if "refresh_token" not in creds_data or not creds_data["refresh_token"]:
                log.warning(f"No refresh token in {file_path}")
                return None, None
            
            # Auto-add 'type' field if missing but has required OAuth fields
            if 'type' not in creds_data and all(key in creds_data for key in ['client_id', 'refresh_token']):
                creds_data['type'] = 'authorized_user'
                log.debug(f"Auto-added 'type' field to credential from file {file_path}")
            
            # Handle different credential formats
            if "access_token" in creds_data and "token" not in creds_data:
                creds_data["token"] = creds_data["access_token"]
            if "scope" in creds_data and "scopes" not in creds_data:
                creds_data["scopes"] = creds_data["scope"].split()
            
            # Handle expiry time format
            if "expiry" in creds_data and isinstance(creds_data["expiry"], str):
                try:
                    exp = creds_data["expiry"]
                    if "+00:00" in exp:
                        parsed = datetime.fromisoformat(exp)
                    elif exp.endswith("Z"):
                        parsed = datetime.fromisoformat(exp.replace('Z', '+00:00'))
                    else:
                        parsed = datetime.fromisoformat(exp)
                    ts = parsed.timestamp()
                    creds_data["expiry"] = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception as e:
                    log.warning(f"Could not parse expiry in {file_path}: {e}")
                    del creds_data["expiry"]
            
            creds = Credentials.from_authorized_user_info(creds_data, creds_data.get("scopes"))
            project_id = creds_data.get("project_id")
            setattr(creds, "project_id", project_id)
            
            # Refresh if needed (but only once per cache cycle)
            if creds.expired and creds.refresh_token:
                try:
                    log.debug(f"Refreshing credentials from {file_path}")
                    creds.refresh(GoogleAuthRequest())
                except Exception as e:
                    log.warning(f"Failed to refresh credentials from {file_path}: {e}")
            
            return creds, project_id
        except Exception as e:
            log.error(f"Failed to load credentials from {file_path}: {e}")
            return None, None

    async def increment_call_count(self):
        """Increment the call count for tracking rotation."""
        async with self._lock:
            self._call_count += 1
            current_calls_per_rotation = get_calls_per_rotation()
            log.debug(f"Call count incremented to {self._call_count}/{current_calls_per_rotation}")

    async def rotate_to_next_credential(self):
        """Manually rotate to next credential (for error recovery)."""
        async with self._lock:
            # Invalidate cache
            self._cached_credentials = None
            self._cached_project_id = None
            self._call_count = 0  # Reset call count
            
            # 重新发现可用凭证文件（过滤掉禁用的文件）
            await self._discover_credential_files()
            
            # 如果没有可用凭证，早期返回
            if not self._credential_files:
                log.error("No available credentials to rotate to")
                return
            
            # Move to next credential
            self._current_credential_index = (self._current_credential_index + 1) % len(self._credential_files)
            log.info(f"Rotated to credential index {self._current_credential_index}, total available: {len(self._credential_files)}")
            
            # 记录当前使用的文件名称供调试
            if self._credential_files:
                current_file = self._credential_files[self._current_credential_index]
                log.info(f"Now using credential: {os.path.basename(current_file)}")

    def get_user_project_id(self, creds: Credentials) -> str:
        """Get user project ID from credentials."""
        project_id = getattr(creds, "project_id", None)
        if project_id:
            return project_id

        raise Exception(
            "Unable to determine Google Cloud project ID. "
            "Ensure credential file contains project_id."
        )

    async def onboard_user(self, creds: Credentials, project_id: str):
        """Optimized user onboarding with caching."""
        # Skip if already onboarded for this session
        if self._onboarding_complete:
            return
        
        async with self._lock:
            # Double-check after acquiring lock
            if self._onboarding_complete:
                return
            
            if creds.expired and creds.refresh_token:
                try:
                    creds.refresh(GoogleAuthRequest())
                except Exception as e:
                    raise Exception(f"Failed to refresh credentials during onboarding: {str(e)}")
            
            headers = {
                "Authorization": f"Bearer {creds.token}",
                "Content-Type": "application/json",
                "User-Agent": get_user_agent(),
            }
            
            load_assist_payload = {
                "cloudaicompanionProject": project_id,
                "metadata": get_client_metadata(project_id),
            }
            
            try:
                # Use reusable HTTP client
                resp = await self._http_client.post(
                    f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist",
                    json=load_assist_payload,
                    headers=headers,
                )
                resp.raise_for_status()
                load_data = resp.json()
                
                # Determine tier
                tier = None
                if load_data.get("currentTier"):
                    tier = load_data["currentTier"]
                else:
                    for allowed_tier in load_data.get("allowedTiers", []):
                        if allowed_tier.get("isDefault"):
                            tier = allowed_tier
                            break
                    
                    if not tier:
                        tier = {
                            "name": "",
                            "description": "",
                            "id": "legacy-tier",
                            "userDefinedCloudaicompanionProject": True,
                        }

                if tier.get("userDefinedCloudaicompanionProject") and not project_id:
                    raise ValueError("This account requires setting the GOOGLE_CLOUD_PROJECT env var.")

                if load_data.get("currentTier"):
                    self._onboarding_complete = True
                    return

                # Onboard user
                onboard_req_payload = {
                    "tierId": tier.get("id"),
                    "cloudaicompanionProject": project_id,
                    "metadata": get_client_metadata(project_id),
                }

                while True:
                    onboard_resp = await self._http_client.post(
                        f"{CODE_ASSIST_ENDPOINT}/v1internal:onboardUser",
                        json=onboard_req_payload,
                        headers=headers,
                    )
                    onboard_resp.raise_for_status()
                    lro_data = onboard_resp.json()

                    if lro_data.get("done"):
                        self._onboarding_complete = True
                        break
                    
                    await asyncio.sleep(5)

            except httpx.HTTPStatusError as e:
                error_text = e.response.text if hasattr(e, 'response') else str(e)
                raise Exception(f"User onboarding failed. Please check your Google Cloud project permissions and try again. Error: {error_text}")
            except Exception as e:
                raise Exception(f"User onboarding failed due to an unexpected error: {str(e)}")

    async def get_credentials_and_project(self) -> Tuple[Optional[Credentials], Optional[str]]:
        """Get both credentials and project ID in one optimized call."""
        if not self._initialized:
            await self.initialize()
        
        # 如果当前没有文件，强制检查一次
        if not self._credential_files:
            log.info("No credentials found, forcing file discovery")
            async with self._lock:
                await self._discover_credential_files()
        
        return await self.get_credentials()