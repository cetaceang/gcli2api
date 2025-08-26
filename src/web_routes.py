"""
Web路由模块 - 处理认证相关的HTTP请求和控制面板功能
用于与上级web.py集成
"""
import os
from log import log
import json
import asyncio
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from .auth_api import (
    create_auth_url, get_auth_status,
    verify_password, generate_auth_token, verify_auth_token,
    batch_upload_credentials, asyncio_complete_auth_flow, 
    load_credentials_from_env, clear_env_credentials
)
from .credential_manager import CredentialManager
import config

# 创建路由器
router = APIRouter()
security = HTTPBearer()

# 创建credential manager实例
credential_manager = CredentialManager()

# WebSocket连接管理
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections.copy():
            try:
                await connection.send_text(message)
            except:
                self.disconnect(connection)

manager = ConnectionManager()

async def ensure_credential_manager_initialized():
    """确保credential manager已初始化"""
    if not credential_manager._initialized:
        await credential_manager.initialize()

async def get_credential_manager():
    """获取全局凭证管理器实例"""
    global credential_manager
    if not credential_manager:
        credential_manager = CredentialManager()
        await credential_manager.initialize()
    return credential_manager

def authenticate(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """验证用户密码（控制面板使用）"""
    from config import get_server_password
    password = get_server_password()
    token = credentials.credentials
    if token != password:
        raise HTTPException(status_code=403, detail="密码错误")
    return token

class LoginRequest(BaseModel):
    password: str

class AuthStartRequest(BaseModel):
    project_id: Optional[str] = None  # 现在是可选的

class AuthCallbackRequest(BaseModel):
    project_id: Optional[str] = None  # 现在是可选的

class CredFileActionRequest(BaseModel):
    filename: str
    action: str  # enable, disable, delete

class CredFileBatchActionRequest(BaseModel):
    action: str  # "enable", "disable", "delete"
    filenames: List[str]  # 批量操作的文件名列表

class ConfigSaveRequest(BaseModel):
    config: dict



def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证认证令牌"""
    if not verify_auth_token(credentials.credentials):
        raise HTTPException(status_code=401, detail="无效的认证令牌")
    return credentials.credentials

@router.get("/", response_class=HTMLResponse)
@router.get("/auth", response_class=HTMLResponse)
async def serve_control_panel():
    """提供统一控制面板（包含认证、文件管理、配置等功能）"""
    try:
        # 读取统一的控制面板HTML文件
        html_file_path = "front/control_panel.html"
        with open(html_file_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="控制面板页面不存在")
    except Exception as e:
        log.error(f"加载控制面板页面失败: {e}")
        raise HTTPException(status_code=500, detail="服务器内部错误")


@router.post("/auth/login")
async def login(request: LoginRequest):
    """用户登录"""
    try:
        if verify_password(request.password):
            token = generate_auth_token()
            return JSONResponse(content={"token": token, "message": "登录成功"})
        else:
            raise HTTPException(status_code=401, detail="密码错误")
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"登录失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auth/start")
async def start_auth(request: AuthStartRequest, token: str = Depends(verify_token)):
    """开始认证流程，支持自动检测项目ID"""
    try:
        # 如果没有提供项目ID，尝试自动检测
        project_id = request.project_id
        if not project_id:
            log.info("用户未提供项目ID，后续将使用自动检测...")
        
        # 使用认证令牌作为用户会话标识
        user_session = token if token else None
        result = create_auth_url(project_id, user_session)
        
        if result['success']:
            return JSONResponse(content={
                "auth_url": result['auth_url'],
                "state": result['state'],
                "auto_project_detection": result.get('auto_project_detection', False),
                "detected_project_id": result.get('detected_project_id')
            })
        else:
            raise HTTPException(status_code=500, detail=result['error'])
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"开始认证流程失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auth/callback")
async def auth_callback(request: AuthCallbackRequest, token: str = Depends(verify_token)):
    """处理认证回调，支持自动检测项目ID"""
    try:
        # 项目ID现在是可选的，在回调处理中进行自动检测
        project_id = request.project_id
        
        # 使用认证令牌作为用户会话标识
        user_session = token if token else None
        # 异步等待OAuth回调完成
        result = await asyncio_complete_auth_flow(project_id, user_session)
        
        if result['success']:
            return JSONResponse(content={
                "credentials": result['credentials'],
                "file_path": result['file_path'],
                "message": "认证成功，凭证已保存",
                "auto_detected_project": result.get('auto_detected_project', False)
            })
        else:
            # 如果需要手动项目ID或项目选择，在响应中标明
            if result.get('requires_manual_project_id'):
                # 使用JSON响应而不是HTTPException来传递复杂数据
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": result['error'],
                        "requires_manual_project_id": True
                    }
                )
            elif result.get('requires_project_selection'):
                # 返回项目列表供用户选择
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": result['error'],
                        "requires_project_selection": True,
                        "available_projects": result['available_projects']
                    }
                )
            else:
                raise HTTPException(status_code=400, detail=result['error'])
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"处理认证回调失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/auth/status/{project_id}")
async def check_auth_status(project_id: str, token: str = Depends(verify_token)):
    """检查认证状态"""
    try:
        if not project_id:
            raise HTTPException(status_code=400, detail="Project ID 不能为空")
        
        status = get_auth_status(project_id)
        return JSONResponse(content=status)
        
    except Exception as e:
        log.error(f"检查认证状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auth/upload")
async def upload_credentials(files: List[UploadFile] = File(...), token: str = Depends(verify_token)):
    """批量上传认证文件"""
    try:
        if not files:
            raise HTTPException(status_code=400, detail="请选择要上传的文件")
        
        files_data = []
        for file in files:
            if not file.filename.endswith('.json'):
                raise HTTPException(status_code=400, detail=f"文件 {file.filename} 不是JSON格式")
            
            content = await file.read()
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                raise HTTPException(status_code=400, detail=f"文件 {file.filename} 编码格式不支持")
            
            files_data.append({
                'filename': file.filename,
                'content': content_str
            })
        
        result = batch_upload_credentials(files_data)
        
        if result['uploaded_count'] > 0:
            return JSONResponse(content={
                "uploaded_count": result['uploaded_count'],
                "total_count": result['total_count'],
                "results": result['results'],
                "message": f"成功上传 {result['uploaded_count']}/{result['total_count']} 个文件"
            })
        else:
            raise HTTPException(status_code=400, detail="没有文件上传成功")
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"批量上传失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/creds/status")
async def get_creds_status(token: str = Depends(verify_token)):
    """获取所有凭证文件的状态"""
    try:
        await ensure_credential_manager_initialized()
        
        # 强制从文件重新加载最新状态
        await credential_manager._load_state()
        
        # 获取状态时不要调用_discover_credential_files，因为它会过滤被禁用的文件
        # 直接获取所有文件的状态
        status = credential_manager.get_creds_status()
        
        # 读取文件内容
        creds_info = {}
        for filename, file_status in status.items():
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = json.loads(f.read())
                
                creds_info[filename] = {
                    "status": file_status,
                    "content": content,
                    "filename": os.path.basename(filename),
                    "size": os.path.getsize(filename),
                    "modified_time": os.path.getmtime(filename),
                    "user_email": file_status.get("user_email")
                }
            except Exception as e:
                log.error(f"读取凭证文件失败 {filename}: {e}")
                creds_info[filename] = {
                    "status": file_status,
                    "content": None,
                    "filename": os.path.basename(filename),
                    "error": str(e)
                }
        
        return JSONResponse(content={"creds": creds_info})
        
    except Exception as e:
        log.error(f"获取凭证状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/creds/action")
async def creds_action(request: CredFileActionRequest, token: str = Depends(verify_token)):
    """对凭证文件执行操作（启用/禁用/删除）"""
    try:
        await ensure_credential_manager_initialized()
        
        log.info(f"Received request: {request}")
        
        filename = request.filename
        action = request.action
        
        log.info(f"Performing action '{action}' on file: {filename}")
        
        # 验证文件路径安全性
        log.info(f"Validating file path: {repr(filename)}")
        log.info(f"Is absolute: {os.path.isabs(filename)}")
        log.info(f"Ends with .json: {filename.endswith('.json')}")
        
        # 如果不是绝对路径，转换为绝对路径
        if not os.path.isabs(filename):
            from config import CREDENTIALS_DIR
            filename = os.path.abspath(os.path.join(CREDENTIALS_DIR, os.path.basename(filename)))
            log.info(f"Converted to absolute path: {filename}")
        
        if not filename.endswith('.json'):
            log.error(f"Invalid file path: {filename} (not a .json file)")
            raise HTTPException(status_code=400, detail=f"无效的文件路径: {filename}")
        
        # 确保文件在CREDENTIALS_DIR内（安全检查）
        from config import CREDENTIALS_DIR
        credentials_dir_abs = os.path.abspath(CREDENTIALS_DIR)
        filename_abs = os.path.abspath(filename)
        if not filename_abs.startswith(credentials_dir_abs):
            log.error(f"Security violation: file outside credentials directory: {filename}")
            raise HTTPException(status_code=400, detail="文件路径不在允许的目录内")
        
        if not os.path.exists(filename):
            log.error(f"File not found: {filename}")
            raise HTTPException(status_code=404, detail="文件不存在")
        
        if action == "enable":
            log.info(f"Web request: ENABLING file {filename}")
            await credential_manager.set_cred_disabled(filename, False)
            log.info(f"Web request: ENABLED file {filename} successfully")
            return JSONResponse(content={"message": f"已启用凭证文件 {os.path.basename(filename)}"})
        
        elif action == "disable":
            log.info(f"Web request: DISABLING file {filename}")
            await credential_manager.set_cred_disabled(filename, True)
            log.info(f"Web request: DISABLED file {filename} successfully")
            return JSONResponse(content={"message": f"已禁用凭证文件 {os.path.basename(filename)}"})
        
        elif action == "delete":
            try:
                os.remove(filename)
                # 从状态中移除（使用相对路径作为键）
                from .credential_manager import _normalize_to_relative_path
                relative_filename = _normalize_to_relative_path(filename)
                
                # 检查并移除状态（支持新旧两种键格式）
                state_keys_to_remove = []
                for key in credential_manager._creds_state.keys():
                    if key == relative_filename or (os.path.isabs(key) and _normalize_to_relative_path(key) == relative_filename):
                        state_keys_to_remove.append(key)
                
                for key in state_keys_to_remove:
                    del credential_manager._creds_state[key]
                
                if state_keys_to_remove:
                    await credential_manager._save_state()
                
                return JSONResponse(content={"message": f"已删除凭证文件 {os.path.basename(filename)}"})
            except OSError as e:
                raise HTTPException(status_code=500, detail=f"删除文件失败: {str(e)}")
        
        else:
            raise HTTPException(status_code=400, detail="无效的操作类型")
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"凭证文件操作失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/creds/batch-action")
async def creds_batch_action(request: CredFileBatchActionRequest, token: str = Depends(verify_token)):
    """批量对凭证文件执行操作（启用/禁用/删除）"""
    try:
        await ensure_credential_manager_initialized()
        
        action = request.action
        filenames = request.filenames
        
        if not filenames:
            raise HTTPException(status_code=400, detail="文件名列表不能为空")
        
        log.info(f"Performing batch action '{action}' on {len(filenames)} files")
        
        success_count = 0
        errors = []
        
        from config import CREDENTIALS_DIR
        
        for filename in filenames:
            try:
                # 验证文件路径安全性
                if not filename.endswith('.json'):
                    errors.append(f"{filename}: 无效的文件类型")
                    continue
                
                # 构建完整路径
                if os.path.isabs(filename):
                    fullpath = filename
                else:
                    fullpath = os.path.abspath(os.path.join(CREDENTIALS_DIR, filename))
                
                # 确保文件在CREDENTIALS_DIR内（安全检查）
                credentials_dir_abs = os.path.abspath(CREDENTIALS_DIR)
                fullpath_abs = os.path.abspath(fullpath)
                if not fullpath_abs.startswith(credentials_dir_abs):
                    errors.append(f"{filename}: 文件路径不在允许的目录内")
                    continue
                
                if not os.path.exists(fullpath):
                    errors.append(f"{filename}: 文件不存在")
                    continue
                
                # 执行相应操作
                if action == "enable":
                    await credential_manager.set_cred_disabled(fullpath, False)
                    success_count += 1
                    
                elif action == "disable":
                    await credential_manager.set_cred_disabled(fullpath, True)
                    success_count += 1
                    
                elif action == "delete":
                    try:
                        os.remove(fullpath)
                        # 从状态中移除（使用相对路径作为键）
                        from .credential_manager import _normalize_to_relative_path
                        relative_filename = _normalize_to_relative_path(fullpath)
                        
                        # 检查并移除状态（支持新旧两种键格式）
                        state_keys_to_remove = []
                        for key in credential_manager._creds_state.keys():
                            if key == relative_filename or (os.path.isabs(key) and _normalize_to_relative_path(key) == relative_filename):
                                state_keys_to_remove.append(key)
                        
                        for key in state_keys_to_remove:
                            del credential_manager._creds_state[key]
                        
                        if state_keys_to_remove:
                            await credential_manager._save_state()
                        
                        success_count += 1
                    except OSError as e:
                        errors.append(f"{filename}: 删除文件失败 - {str(e)}")
                        continue
                else:
                    errors.append(f"{filename}: 无效的操作类型")
                    continue
                    
            except Exception as e:
                log.error(f"Processing {filename} failed: {e}")
                errors.append(f"{filename}: 处理失败 - {str(e)}")
                continue
        
        # 构建返回消息
        result_message = f"批量操作完成：成功处理 {success_count}/{len(filenames)} 个文件"
        if errors:
            result_message += f"\n错误详情：\n" + "\n".join(errors)
            
        response_data = {
            "success_count": success_count,
            "total_count": len(filenames),
            "errors": errors,
            "message": result_message
        }
        
        return JSONResponse(content=response_data)
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"批量凭证文件操作失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/creds/download/{filename}")
async def download_cred_file(filename: str, token: str = Depends(verify_token)):
    """下载单个凭证文件"""
    try:
        # 构建完整路径
        from config import CREDENTIALS_DIR
        filepath = os.path.join(CREDENTIALS_DIR, filename)
        
        # 验证文件路径安全性
        if not filepath.endswith('.json') or not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="文件不存在")
        
        # 读取文件内容
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        from fastapi.responses import Response
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"下载凭证文件失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/creds/fetch-email/{filename}")
async def fetch_user_email(filename: str, token: str = Depends(verify_token)):
    """获取指定凭证文件的用户邮箱地址"""
    try:
        await ensure_credential_manager_initialized()
        
        # 构建完整路径
        from config import CREDENTIALS_DIR
        if not os.path.isabs(filename):
            filepath = os.path.abspath(os.path.join(CREDENTIALS_DIR, os.path.basename(filename)))
        else:
            filepath = filename
        
        # 验证文件路径安全性
        if not filepath.endswith('.json') or not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="文件不存在")
        
        # 获取用户邮箱
        email = await credential_manager.get_or_fetch_user_email(filepath)
        
        if email:
            return JSONResponse(content={
                "filename": os.path.basename(filepath),
                "user_email": email,
                "message": "成功获取用户邮箱"
            })
        else:
            return JSONResponse(content={
                "filename": os.path.basename(filepath),
                "user_email": None,
                "message": "无法获取用户邮箱，可能凭证已过期或权限不足"
            }, status_code=400)
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取用户邮箱失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/creds/refresh-all-emails")
async def refresh_all_user_emails(token: str = Depends(verify_token)):
    """刷新所有凭证文件的用户邮箱地址"""
    try:
        await ensure_credential_manager_initialized()
        
        # 获取所有凭证文件
        from config import CREDENTIALS_DIR
        import glob
        
        json_files = glob.glob(os.path.join(CREDENTIALS_DIR, "*.json"))
        
        results = []
        success_count = 0
        
        for filepath in json_files:
            try:
                email = await credential_manager.get_or_fetch_user_email(filepath)
                if email:
                    success_count += 1
                    results.append({
                        "filename": os.path.basename(filepath),
                        "user_email": email,
                        "success": True
                    })
                else:
                    results.append({
                        "filename": os.path.basename(filepath),
                        "user_email": None,
                        "success": False,
                        "error": "无法获取邮箱"
                    })
            except Exception as e:
                results.append({
                    "filename": os.path.basename(filepath),
                    "user_email": None,
                    "success": False,
                    "error": str(e)
                })
        
        return JSONResponse(content={
            "success_count": success_count,
            "total_count": len(json_files),
            "results": results,
            "message": f"成功获取 {success_count}/{len(json_files)} 个邮箱地址"
        })
        
    except Exception as e:
        log.error(f"批量获取用户邮箱失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/creds/download-all")
async def download_all_creds(token: str = Depends(verify_token)):
    """打包下载所有凭证文件"""
    try:
        import zipfile
        import io
        from config import CREDENTIALS_DIR
        
        # 创建内存中的ZIP文件
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # 遍历所有JSON文件
            for filename in os.listdir(CREDENTIALS_DIR):
                if filename.endswith('.json'):
                    filepath = os.path.join(CREDENTIALS_DIR, filename)
                    if os.path.isfile(filepath):
                        zip_file.write(filepath, filename)
        
        zip_buffer.seek(0)
        
        from fastapi.responses import Response
        return Response(
            content=zip_buffer.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=credentials.zip"}
        )
        
    except Exception as e:
        log.error(f"打包下载失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config/get")
async def get_config(token: str = Depends(verify_token)):
    """获取当前配置"""
    try:
        await ensure_credential_manager_initialized()
        
        # 导入配置相关模块
        import config
        import toml
        
        # 读取当前配置（包括环境变量和TOML文件中的配置）
        current_config = {}
        env_locked = []
        
        # 基础配置
        current_config["code_assist_endpoint"] = config.get_code_assist_endpoint()
        current_config["credentials_dir"] = config.get_credentials_dir()
        current_config["proxy"] = config.get_proxy_config() or ""
        
        # 检查环境变量锁定状态
        if os.getenv("CODE_ASSIST_ENDPOINT"):
            env_locked.append("code_assist_endpoint")
        if os.getenv("CREDENTIALS_DIR"):
            env_locked.append("credentials_dir")
        if os.getenv("PROXY"):
            env_locked.append("proxy")
        
        # 自动封禁配置
        current_config["auto_ban_enabled"] = config.get_auto_ban_enabled()
        current_config["auto_ban_error_codes"] = config.get_auto_ban_error_codes()
        
        # 检查环境变量锁定状态
        if os.getenv("AUTO_BAN"):
            env_locked.append("auto_ban_enabled")
        
        # 尝试从config.toml文件读取额外配置
        try:
            config_file = os.path.join(config.CREDENTIALS_DIR, "config.toml")
            if os.path.exists(config_file):
                with open(config_file, "r", encoding="utf-8") as f:
                    toml_data = toml.load(f)
                
                # 合并TOML配置（不覆盖环境变量）
                for key, value in toml_data.items():
                    if key not in env_locked:
                        current_config[key] = value
        except Exception as e:
            log.warning(f"读取TOML配置失败: {e}")
        
        # 性能配置
        current_config["calls_per_rotation"] = config.get_calls_per_rotation()
        current_config["http_timeout"] = config.get_http_timeout()
        current_config["max_connections"] = config.get_max_connections()
        
        # 429重试配置
        current_config["retry_429_max_retries"] = config.get_retry_429_max_retries()
        current_config["retry_429_enabled"] = config.get_retry_429_enabled()
        current_config["retry_429_interval"] = config.get_retry_429_interval()
        
        # 日志配置
        current_config["log_level"] = config.get_log_level()
        current_config["log_file"] = config.get_log_file()
        
        # 抗截断配置
        current_config["anti_truncation_max_attempts"] = config.get_anti_truncation_max_attempts()
        
        # 服务器配置
        current_config["host"] = config.get_server_host()
        current_config["port"] = config.get_server_port()
        current_config["password"] = config.get_server_password()
        
        # 检查其他环境变量锁定状态
        if os.getenv("RETRY_429_MAX_RETRIES"):
            env_locked.append("retry_429_max_retries")
        if os.getenv("RETRY_429_ENABLED"):
            env_locked.append("retry_429_enabled")
        if os.getenv("RETRY_429_INTERVAL"):
            env_locked.append("retry_429_interval")
        if os.getenv("LOG_LEVEL"):
            env_locked.append("log_level")
        if os.getenv("LOG_FILE"):
            env_locked.append("log_file")
        if os.getenv("ANTI_TRUNCATION_MAX_ATTEMPTS"):
            env_locked.append("anti_truncation_max_attempts")
        if os.getenv("HOST"):
            env_locked.append("host")
        if os.getenv("PORT"):
            env_locked.append("port")
        if os.getenv("PASSWORD"):
            env_locked.append("password")
        
        return JSONResponse(content={
            "config": current_config,
            "env_locked": env_locked
        })
        
    except Exception as e:
        log.error(f"获取配置失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/config/save")
async def save_config(request: ConfigSaveRequest, token: str = Depends(verify_token)):
    """保存配置到TOML文件"""
    try:
        await ensure_credential_manager_initialized()
        
        import config
        import toml
        
        new_config = request.config
        
        log.info(f"收到的配置数据: {list(new_config.keys())}")
        log.info(f"收到的password值: {new_config.get('password', 'NOT_FOUND')}")
        
        # 验证配置项
        if "calls_per_rotation" in new_config:
            if not isinstance(new_config["calls_per_rotation"], int) or new_config["calls_per_rotation"] < 1:
                raise HTTPException(status_code=400, detail="凭证轮换调用次数必须是大于0的整数")
        
        if "http_timeout" in new_config:
            if not isinstance(new_config["http_timeout"], int) or new_config["http_timeout"] < 5:
                raise HTTPException(status_code=400, detail="HTTP超时时间必须是大于等于5的整数")
        
        if "max_connections" in new_config:
            if not isinstance(new_config["max_connections"], int) or new_config["max_connections"] < 10:
                raise HTTPException(status_code=400, detail="最大连接数必须是大于等于10的整数")
        
        if "retry_429_max_retries" in new_config:
            if not isinstance(new_config["retry_429_max_retries"], int) or new_config["retry_429_max_retries"] < 0:
                raise HTTPException(status_code=400, detail="最大429重试次数必须是大于等于0的整数")
        
        if "retry_429_enabled" in new_config:
            if not isinstance(new_config["retry_429_enabled"], bool):
                raise HTTPException(status_code=400, detail="429重试开关必须是布尔值")
        
        # 验证新的配置项
        if "retry_429_interval" in new_config:
            try:
                interval = float(new_config["retry_429_interval"])
                if interval < 0.01 or interval > 10:
                    raise HTTPException(status_code=400, detail="429重试间隔必须在0.01-10秒之间")
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="429重试间隔必须是有效的数字")
        
        if "log_level" in new_config:
            valid_levels = ["debug", "info", "warning", "error", "critical"]
            if new_config["log_level"].lower() not in valid_levels:
                raise HTTPException(status_code=400, detail=f"日志级别必须是以下之一: {', '.join(valid_levels)}")
        
        if "anti_truncation_max_attempts" in new_config:
            if not isinstance(new_config["anti_truncation_max_attempts"], int) or new_config["anti_truncation_max_attempts"] < 1 or new_config["anti_truncation_max_attempts"] > 10:
                raise HTTPException(status_code=400, detail="抗截断最大重试次数必须是1-10之间的整数")
        
        # 验证服务器配置
        if "host" in new_config:
            if not isinstance(new_config["host"], str) or not new_config["host"].strip():
                raise HTTPException(status_code=400, detail="服务器主机地址不能为空")
        
        if "port" in new_config:
            if not isinstance(new_config["port"], int) or new_config["port"] < 1 or new_config["port"] > 65535:
                raise HTTPException(status_code=400, detail="端口号必须是1-65535之间的整数")
        
        if "password" in new_config:
            if not isinstance(new_config["password"], str):
                raise HTTPException(status_code=400, detail="访问密码必须是字符串")
        
        # 读取现有的配置文件
        config_file = os.path.join(config.CREDENTIALS_DIR, "config.toml")
        existing_config = {}
        
        try:
            if os.path.exists(config_file):
                with open(config_file, "r", encoding="utf-8") as f:
                    existing_config = toml.load(f)
        except Exception as e:
            log.warning(f"读取现有配置文件失败: {e}")
        
        # 只更新不被环境变量锁定的配置项
        env_locked_keys = set()
        if os.getenv("CODE_ASSIST_ENDPOINT"):
            env_locked_keys.add("code_assist_endpoint")
        if os.getenv("CREDENTIALS_DIR"):
            env_locked_keys.add("credentials_dir")
        if os.getenv("PROXY"):
            env_locked_keys.add("proxy")
        if os.getenv("AUTO_BAN"):
            env_locked_keys.add("auto_ban_enabled")
        if os.getenv("RETRY_429_MAX_RETRIES"):
            env_locked_keys.add("retry_429_max_retries")
        if os.getenv("RETRY_429_ENABLED"):
            env_locked_keys.add("retry_429_enabled")
        if os.getenv("RETRY_429_INTERVAL"):
            env_locked_keys.add("retry_429_interval")
        if os.getenv("LOG_LEVEL"):
            env_locked_keys.add("log_level")
        if os.getenv("LOG_FILE"):
            env_locked_keys.add("log_file")
        if os.getenv("ANTI_TRUNCATION_MAX_ATTEMPTS"):
            env_locked_keys.add("anti_truncation_max_attempts")
        if os.getenv("HOST"):
            env_locked_keys.add("host")
        if os.getenv("PORT"):
            env_locked_keys.add("port")
        if os.getenv("PASSWORD"):
            env_locked_keys.add("password")
        
        for key, value in new_config.items():
            if key not in env_locked_keys:
                existing_config[key] = value
                if key == 'password':
                    log.info(f"设置password字段为: {value}")
        
        log.info(f"最终保存的existing_config中password = {existing_config.get('password', 'NOT_FOUND')}")
        
        # 使用config模块的保存函数
        config.save_config_to_toml(existing_config)
        
        # 验证保存后的结果
        test_password = config.get_server_password()
        log.info(f"保存后立即读取的密码: {test_password}")
        
        # 热更新配置到内存中的模块（如果可能）
        try:
            # save_config_to_toml已经更新了缓存，不需要reload
            pass
            
            # 更新credential_manager的配置
            if "calls_per_rotation" in new_config and "calls_per_rotation" not in env_locked_keys:
                credential_manager._calls_per_rotation = new_config["calls_per_rotation"]
            
            # 重新初始化HTTP客户端以应用新的代理配置（如果代理配置更改了）
            if "proxy" in new_config and "proxy" not in env_locked_keys:
                # 重新创建HTTP客户端
                if credential_manager._http_client:
                    await credential_manager._http_client.aclose()
                    proxy = config.get_proxy_config()
                    client_kwargs = {
                        "timeout": new_config.get("http_timeout", 30),
                        "limits": __import__('httpx').Limits(
                            max_keepalive_connections=20, 
                            max_connections=new_config.get("max_connections", 100)
                        )
                    }
                    if proxy:
                        client_kwargs["proxy"] = proxy
                    credential_manager._http_client = __import__('httpx').AsyncClient(**client_kwargs)
        except Exception as e:
            log.warning(f"热更新配置失败: {e}")
        
        return JSONResponse(content={
            "message": "配置保存成功",
            "saved_config": {k: v for k, v in new_config.items() if k not in env_locked_keys}
        })
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"保存配置失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auth/load-env-creds")
async def load_env_credentials(token: str = Depends(verify_token)):
    """从环境变量加载凭证文件"""
    try:
        result = load_credentials_from_env()
        
        if result['loaded_count'] > 0:
            return JSONResponse(content={
                "loaded_count": result['loaded_count'],
                "total_count": result['total_count'],
                "results": result['results'],
                "message": result['message']
            })
        else:
            return JSONResponse(content={
                "loaded_count": 0,
                "total_count": result['total_count'],
                "message": result['message'],
                "results": result['results']
            })
            
    except Exception as e:
        log.error(f"从环境变量加载凭证失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/auth/env-creds")
async def clear_env_creds(token: str = Depends(verify_token)):
    """清除所有从环境变量导入的凭证文件"""
    try:
        result = clear_env_credentials()
        
        if 'error' in result:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return JSONResponse(content={
            "deleted_count": result['deleted_count'],
            "deleted_files": result.get('deleted_files', []),
            "message": result['message']
        })
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"清除环境变量凭证失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/auth/env-creds-status")
async def get_env_creds_status(token: str = Depends(verify_token)):
    """获取环境变量凭证状态"""
    try:
        # 检查有哪些环境变量可用
        available_env_vars = {key: "***已设置***" for key, value in os.environ.items() 
                              if key.startswith('GCLI_CREDS_') and value.strip()}
        
        # 检查自动加载设置
        auto_load_enabled = config.get_auto_load_env_creds()
        
        # 统计已存在的环境变量凭证文件
        from config import CREDENTIALS_DIR
        existing_env_files = []
        if os.path.exists(CREDENTIALS_DIR):
            for filename in os.listdir(CREDENTIALS_DIR):
                if filename.startswith('env-') and filename.endswith('.json'):
                    existing_env_files.append(filename)
        
        return JSONResponse(content={
            "available_env_vars": available_env_vars,
            "auto_load_enabled": auto_load_enabled,
            "existing_env_files_count": len(existing_env_files),
            "existing_env_files": existing_env_files
        })
        
    except Exception as e:
        log.error(f"获取环境变量凭证状态失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# 实时日志WebSocket (Real-time Logs WebSocket)
# =============================================================================

@router.post("/auth/logs/clear")
async def clear_logs(token: str = Depends(verify_token)):
    """清空日志文件"""
    try:
        import config
        log_file_path = config.get_log_file()
        
        # 检查日志文件是否存在
        if os.path.exists(log_file_path):
            # 清空文件内容（保留文件）
            with open(log_file_path, 'w', encoding='utf-8') as f:
                f.write('')
            log.info(f"日志文件已清空: {log_file_path}")
            return JSONResponse(content={"message": f"日志文件已清空: {os.path.basename(log_file_path)}"})
        else:
            return JSONResponse(content={"message": "日志文件不存在"})
            
    except Exception as e:
        log.error(f"清空日志文件失败: {e}")
        raise HTTPException(status_code=500, detail=f"清空日志文件失败: {str(e)}")

@router.get("/auth/logs/download")
async def download_logs(token: str = Depends(verify_token)):
    """下载日志文件"""
    try:
        import config
        log_file_path = config.get_log_file()
        
        # 检查日志文件是否存在
        if not os.path.exists(log_file_path):
            raise HTTPException(status_code=404, detail="日志文件不存在")
        
        # 检查文件是否为空
        file_size = os.path.getsize(log_file_path)
        if file_size == 0:
            raise HTTPException(status_code=404, detail="日志文件为空")
        
        # 生成文件名（包含时间戳）
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"gcli2api_logs_{timestamp}.txt"
        
        log.info(f"下载日志文件: {log_file_path}")
        
        return FileResponse(
            path=log_file_path,
            filename=filename,
            media_type='text/plain',
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
            
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"下载日志文件失败: {e}")
        raise HTTPException(status_code=500, detail=f"下载日志文件失败: {str(e)}")

@router.websocket("/auth/logs/stream")
async def websocket_logs(websocket: WebSocket):
    """WebSocket端点，用于实时日志流"""
    await manager.connect(websocket)
    try:
        # 从配置获取日志文件路径
        import config
        log_file_path = config.get_log_file()
        if os.path.exists(log_file_path):
            try:
                with open(log_file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    # 发送最后100行
                    for line in lines[-100:]:
                        await websocket.send_text(line.strip())
            except Exception as e:
                await websocket.send_text(f"Error reading log file: {e}")
        
        # 监控日志文件变化（简单实现）
        last_size = os.path.getsize(log_file_path) if os.path.exists(log_file_path) else 0
        
        while True:
            await asyncio.sleep(1)
            
            if os.path.exists(log_file_path):
                current_size = os.path.getsize(log_file_path)
                if current_size > last_size:
                    # 读取新增内容
                    with open(log_file_path, "r", encoding="utf-8") as f:
                        f.seek(last_size)
                        new_content = f.read()
                        for line in new_content.splitlines():
                            if line.strip():
                                await websocket.send_text(line)
                    last_size = current_size
                    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        log.error(f"WebSocket logs error: {e}")
        manager.disconnect(websocket)

