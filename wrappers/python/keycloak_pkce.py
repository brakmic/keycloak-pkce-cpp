import os
import ctypes
from ctypes import (c_char_p, c_void_p, c_bool, c_int, c_uint16,
                    c_size_t, c_uint64, POINTER, Structure)

# ------------------------------------------------------------------------------
# 1) C type definitions matching kc_pkce.h
# ------------------------------------------------------------------------------
class kc_pkce_token_info_t(Structure):
    _fields_ = [
        ("access_token",      ctypes.c_char_p),
        ("refresh_token",     ctypes.c_char_p),
        ("id_token",          ctypes.c_char_p),
        ("token_type",        ctypes.c_char_p),
        ("expires_in",        c_uint64),
        ("error",             ctypes.c_char_p),
        ("error_description", ctypes.c_char_p),
    ]

class kc_pkce_proxy_config_t(Structure):
    _fields_ = [
        ("host", c_char_p),
        ("port", c_uint16),
    ]

# Opaque pointers
kc_pkce_handle_t  = c_void_p
kc_pkce_config_t  = c_void_p

# Load the library
lib_path = os.environ.get("KC_PKCE_LIB", "libkc_pkce.so")
_kc = ctypes.CDLL(lib_path)

# ------------------------------------------------------------------------------
# 2) Declare function signatures
# ------------------------------------------------------------------------------
# int kc_pkce_config_create(kc_pkce_config_t* config);
_kc.kc_pkce_config_create.argtypes  = [POINTER(kc_pkce_config_t)]
_kc.kc_pkce_config_create.restype   = c_int

# int kc_pkce_config_load_file(kc_pkce_config_t config, const char* path);
_kc.kc_pkce_config_load_file.argtypes = [kc_pkce_config_t, c_char_p]
_kc.kc_pkce_config_load_file.restype  = c_int

# int kc_pkce_set_proxy_config(const kc_pkce_proxy_config_t* proxy);
_kc.kc_pkce_set_proxy_config.argtypes = [POINTER(kc_pkce_proxy_config_t)]
_kc.kc_pkce_set_proxy_config.restype  = c_int

# int kc_pkce_create(kc_pkce_handle_t* handle, const kc_pkce_config_t config);
_kc.kc_pkce_create.argtypes = [POINTER(kc_pkce_handle_t), kc_pkce_config_t]
_kc.kc_pkce_create.restype  = c_int

# int kc_pkce_set_redirect_uri(kc_pkce_handle_t handle, const char* uri);
_kc.kc_pkce_set_redirect_uri.argtypes = [kc_pkce_handle_t, c_char_p]
_kc.kc_pkce_set_redirect_uri.restype  = c_int

# int kc_pkce_create_auth_url(kc_pkce_handle_t handle, char* buffer, size_t size);
_kc.kc_pkce_create_auth_url.argtypes = [kc_pkce_handle_t, c_char_p, c_size_t]
_kc.kc_pkce_create_auth_url.restype  = c_int

# int kc_pkce_handle_callback(kc_pkce_handle_t handle, const char* code,
#                            const char* state, kc_pkce_token_info_t* token_info);
_kc.kc_pkce_handle_callback.argtypes = [
    kc_pkce_handle_t, c_char_p, c_char_p, POINTER(kc_pkce_token_info_t)
]
_kc.kc_pkce_handle_callback.restype  = c_int

# bool kc_pkce_validate_session(kc_pkce_handle_t handle, const char* access_token);
_kc.kc_pkce_validate_session.argtypes = [kc_pkce_handle_t, c_char_p]
_kc.kc_pkce_validate_session.restype  = c_bool

# void kc_pkce_free_token_info(kc_pkce_token_info_t* token_info);
_kc.kc_pkce_free_token_info.argtypes = [POINTER(kc_pkce_token_info_t)]
_kc.kc_pkce_free_token_info.restype  = None

# Cleanup
# void kc_pkce_destroy(kc_pkce_handle_t handle);
_kc.kc_pkce_destroy.argtypes = [kc_pkce_handle_t]
_kc.kc_pkce_destroy.restype  = None

# void kc_pkce_config_destroy(kc_pkce_config_t config);
_kc.kc_pkce_config_destroy.argtypes = [kc_pkce_config_t]
_kc.kc_pkce_config_destroy.restype  = None


# ------------------------------------------------------------------------------
# 3) Python class that wraps the C API
# ------------------------------------------------------------------------------
class KeycloakPKCE:
    def __init__(self, config_path: str):
        """
        Create + load config. Do not fully create the PKCE instance until self.init().
        """
        self._config = kc_pkce_config_t()
        self._handle = kc_pkce_handle_t()
        self._initialized = False
        
        # Step A: create config
        rc = _kc.kc_pkce_config_create(ctypes.byref(self._config))
        if rc != 0:
            raise RuntimeError("Failed to create PKCE config")
        
        # Step B: load config file
        rc = _kc.kc_pkce_config_load_file(self._config, config_path.encode('utf-8'))
        if rc != 0:
            self.destroy()
            raise RuntimeError("Failed to load config file")

    def set_proxy(self, host: str, port: int):
        """
        (Optional) set global proxy if needed
        """
        proxy_cfg = kc_pkce_proxy_config_t()
        proxy_cfg.host = host.encode('utf-8')
        proxy_cfg.port = port
        rc = _kc.kc_pkce_set_proxy_config(ctypes.byref(proxy_cfg))
        if rc != 0:
            raise RuntimeError("Failed to set proxy configuration")

    def init(self):
        """
        Actually create the PKCE instance. Must be done before calling get_auth_url / handle_callback, etc.
        """
        if self._initialized:
            return
        rc = _kc.kc_pkce_create(ctypes.byref(self._handle), self._config)
        if rc != 0:
            raise RuntimeError("Failed to create PKCE instance")
        self._initialized = True

    def set_redirect_uri(self, redirect_uri: str):
        if not self._initialized:
            raise RuntimeError("Must call init() before set_redirect_uri()")
        rc = _kc.kc_pkce_set_redirect_uri(self._handle, redirect_uri.encode('utf-8'))
        if rc != 0:
            raise RuntimeError("Failed to set redirect URI")

    def get_auth_url(self) -> str:
        """
        Create the PKCE authorization URL
        """
        if not self._initialized:
            raise RuntimeError("PKCE not initialized")
        BUFFER_SIZE = 4096
        buf = ctypes.create_string_buffer(BUFFER_SIZE)
        rc = _kc.kc_pkce_create_auth_url(self._handle, buf, BUFFER_SIZE)
        if rc != 0:
            raise RuntimeError("Failed to create auth URL")
        return buf.value.decode('utf-8')

    def handle_callback(self, code: str, state: str) -> dict:
        """
        Exchanges code + state for tokens
        """
        if not self._initialized:
            raise RuntimeError("PKCE not initialized")
        token_info = kc_pkce_token_info_t()
        rc = _kc.kc_pkce_handle_callback(
            self._handle, code.encode('utf-8'), state.encode('utf-8'),
            ctypes.byref(token_info)
        )
        if rc != 0:
            # Extract error info if any
            err_msg  = token_info.error and token_info.error.decode('utf-8') or "unknown"
            err_desc = token_info.error_description and token_info.error_description.decode('utf-8') or ""
            _kc.kc_pkce_free_token_info(ctypes.byref(token_info))
            raise RuntimeError(f"Token exchange failed: {err_msg} [{err_desc}]")
        
        tokens = {
            "access_token":  token_info.access_token and token_info.access_token.decode('utf-8'),
            "refresh_token": token_info.refresh_token and token_info.refresh_token.decode('utf-8'),
            "id_token":      token_info.id_token and token_info.id_token.decode('utf-8'),
            "token_type":    token_info.token_type and token_info.token_type.decode('utf-8'),
            "expires_in":    int(token_info.expires_in),
        }
        _kc.kc_pkce_free_token_info(ctypes.byref(token_info))
        return tokens

    def validate_session(self, token: str) -> bool:
        """
        Check if the given access token is valid
        """
        if not self._initialized:
            return False
        return bool(_kc.kc_pkce_validate_session(self._handle, token.encode('utf-8')))

    def destroy(self):
        """
        Cleanup
        """
        if self._handle:
            _kc.kc_pkce_destroy(self._handle)
            self._handle = None
        if self._config:
            _kc.kc_pkce_config_destroy(self._config)
            self._config = None
        self._initialized = False

    def __del__(self):
        # In case destroy() wasn't called
        self.destroy()
