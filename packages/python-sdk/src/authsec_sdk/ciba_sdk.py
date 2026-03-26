"""
AuthSec CIBA SDK - Passwordless Authentication for Voice Clients

Python SDK for integrating CIBA (Client-Initiated Backchannel Authentication) 
and TOTP verification into voice clients and other applications.

Supports both Admin and End-User (tenant) authentication flows:
- Admin flow: email only (original flow)
- Tenant flow: email + client_id (multi-client architecture)
"""

import json
import os
import requests
import time
import certifi


def _is_local_base_url(base_url):
    return "localhost" in base_url or "127.0.0.1" in base_url


def _request_kwargs(base_url, timeout=None):
    kwargs = {}
    if timeout is not None:
        kwargs["timeout"] = timeout
    kwargs["verify"] = False if _is_local_base_url(base_url) else certifi.where()
    return kwargs


def _read_ciba_base_url_from_config():
    """Read ciba_base_url from .authsec.json in cwd, or return None."""
    try:
        path = os.path.join(os.getcwd(), ".authsec.json")
        if os.path.isfile(path):
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data.get("ciba_base_url")
    except Exception:
        pass
    return None


class CIBAClient:
    """
    Python SDK for customers to integrate AuthSec into their own voice clients.
    Handles the technical execution of polling, verification, and initiation.
    
    Supports both Admin and End-User (tenant) authentication flows:
    - Admin flow: email only (original flow)
    - Tenant flow: email + client_id (multi-client architecture)
    
    Example usage:
        # Initialize for tenant flow
        from authsec_sdk import CIBAClient
        
        client = CIBAClient(client_id="your_tenant_client_id")
        
        # CIBA: Send push notification
        result = client.initiate_app_approval("user@example.com")
        auth_req_id = result["auth_req_id"]
        
        # Poll for approval
        approval = client.poll_for_approval("user@example.com", auth_req_id)
        if approval["status"] == "approved":
            token = approval["token"]
        
        # Or use TOTP verification
        result = client.verify_totp("user@example.com", "123456")
    """
    
    def __init__(self, client_id=None, base_url=None):
        """
        Initialize the AuthSec SDK.

        Args:
            client_id: Optional client ID for tenant/end-user flow. If provided, uses tenant endpoints.
                      If None, uses admin endpoints.
            base_url: Optional base URL override.
                      Priority: explicit param → .authsec.json → hardcoded default.
        """
        self.base_url = base_url or _read_ciba_base_url_from_config() or "https://prod.api.authsec.ai"
        self.client_id = client_id  # Optional: for tenant multi-client architecture
        self.active_polls = {}  # Map email -> cancellation_flag
        self.retry_counts = {}  # Map email -> int

    def initiate_app_approval(self, email):
        """
        Triggers a CIBA push notification and cancels any existing poll for this user.
        
        - If client_id is set: uses tenant endpoint (/tenant/ciba/initiate)
        - If client_id is None: uses admin endpoint (/ciba/initiate)
        
        Args:
            email: User's email address
            
        Returns:
            dict: Response containing auth_req_id for polling
        """
        self.retry_counts[email] = 0
        if email in self.active_polls:
            self.active_polls[email] = True

        if self.client_id:
            # Tenant/End-User flow
            endpoint = f"{self.base_url}/authsec/uflow/auth/tenant/ciba/initiate"
            payload = {
                "client_id": self.client_id,
                "email": email,
                "binding_message": "Authentication requested via Voice SDK"
            }
        else:
            # Admin flow
            endpoint = f"{self.base_url}/authsec/uflow/auth/ciba/initiate"
            payload = {"login_hint": email, "binding_message": "Authentication requested via Voice SDK"}
        
        try:
            response = requests.post(
                endpoint,
                json=payload,
                **_request_kwargs(self.base_url, timeout=10),
            )
            return response.json()
        except requests.RequestException as e:
            return {"success": False, "error": str(e)}

    def verify_totp(self, email, code):
        """
        Verifies a TOTP code for authentication.
        
        - If client_id is set: uses tenant endpoint (/tenant/totp/login)
        - If client_id is None: uses admin endpoint (/totp/login)
        
        Args:
            email: User's email address
            code: 6-digit TOTP code
            
        Returns:
            dict: Result with success status, token (if successful), and remaining retries
        """
        if email not in self.retry_counts:
            self.retry_counts[email] = 0
        if self.retry_counts[email] >= 3:
            return {"success": False, "error": "too_many_retries", "remaining": 0}

        if self.client_id:
            # Tenant/End-User flow
            endpoint = f"{self.base_url}/authsec/uflow/auth/tenant/totp/login"
            payload = {"client_id": self.client_id, "email": email, "totp_code": code}
        else:
            # Admin flow
            endpoint = f"{self.base_url}/authsec/uflow/auth/totp/login"
            payload = {"email": email, "totp_code": code}
        
        try:
            response = requests.post(
                endpoint,
                json=payload,
                **_request_kwargs(self.base_url, timeout=10),
            )
            res_data = response.json()

            # The API returns 'token' or 'access_token'
            token = res_data.get("token") or res_data.get("access_token")

            if token or res_data.get("success") is True:
                self.retry_counts[email] = 0
                return {**res_data, "success": True, "token": token, "remaining": 3}
            else:
                self.retry_counts[email] += 1
                return {"success": False, "error": "invalid_code", "remaining": 3 - self.retry_counts[email]}
        except Exception as e:
            return {"success": False, "error": str(e), "remaining": 3 - self.retry_counts[email]}

    def poll_for_approval(self, email, auth_req_id, interval=5, timeout=300):
        """
        Polls for CIBA approval status.
        
        - If client_id is set: uses tenant endpoint (/tenant/ciba/token)
        - If client_id is None: uses admin endpoint (/ciba/token)
        
        Args:
            email: User's email address
            auth_req_id: The auth request ID from initiate_app_approval
            interval: Polling interval in seconds (default: 5)
            timeout: Maximum time to poll in seconds (default: 300)
            
        Returns:
            dict: Status with 'approved', 'cancelled', 'timeout', or error status
        """
        self.active_polls[email] = False
        
        if self.client_id:
            # Tenant/End-User flow
            endpoint = f"{self.base_url}/authsec/uflow/auth/tenant/ciba/token"
            payload = {"client_id": self.client_id, "auth_req_id": auth_req_id}
        else:
            # Admin flow
            endpoint = f"{self.base_url}/authsec/uflow/auth/ciba/token"
            payload = {"auth_req_id": auth_req_id}
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.active_polls.get(email) is True:
                return {"status": "cancelled"}
            try:
                response = requests.post(
                    endpoint,
                    json=payload,
                    **_request_kwargs(self.base_url, timeout=10),
                )
                data = response.json()
            except requests.RequestException as e:
                return {"status": "error", "error": str(e)}

            # Handle both key names
            token = data.get("access_token") or data.get("token")

            if token:
                return {"status": "approved", "token": token}
            if data.get("error") in ["access_denied", "expired_token"]:
                return {"status": data.get("error")}
            time.sleep(interval)
            if timeout <= 2:
                break  # Short check for manual check
        return {"status": "timeout"}

    def cancel_approval(self, email):
        """
        Cancels any ongoing poll and resets retry logic for the user.
        
        Args:
            email: User's email address
            
        Returns:
            dict: Cancellation status
        """
        self.active_polls[email] = True
        self.retry_counts[email] = 0
        return {"status": "cancelled"}

    def login_end_user(self, email, password):
        """
        Logs in a tenant end-user and returns the AuthSec JWT.

        Requires client_id to be set.
        """
        if not self.client_id:
            return {"success": False, "error": "client_id_required"}

        endpoint = f"{self.base_url}/authsec/uflow/user/login"
        payload = {"client_id": self.client_id, "email": email, "password": password}

        try:
            response = requests.post(
                endpoint,
                json=payload,
                **_request_kwargs(self.base_url, timeout=10),
            )
            return response.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_end_user_mfa_status(self, email, tenant_id):
        """
        Inspects the effective MFA state for a tenant end-user.

        This is used when the legacy /uflow/user/login route only returns a bare
        `mfa_required` flag without method details.
        """
        if _is_local_base_url(self.base_url):
            endpoint = f"{self.base_url}/webauthn/mfa/loginStatus"
        else:
            endpoint = f"{self.base_url}/authsec/webauthn/mfa/loginStatus"
        payload = {"email": email, "tenant_id": tenant_id}

        try:
            response = requests.post(
                endpoint,
                json=payload,
                **_request_kwargs(self.base_url, timeout=10),
            )
            return response.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_end_user_mfa_status_by_client(self, email):
        """
        Inspects end-user MFA state using the tenant client_id-aware endpoint.

        This is the preferred probe for SDK-driven tenant users because the
        login status route keyed by client_id matches the same tenant context
        used by CIBA/TOTP login.
        """
        if not self.client_id:
            return {"success": False, "error": "client_id_required"}

        endpoint = f"{self.base_url}/authsec/webauthn/enduser/mfa/loginStatus"
        payload = {"email": email, "client_id": self.client_id}

        try:
            response = requests.post(
                endpoint,
                json=payload,
                **_request_kwargs(self.base_url, timeout=10),
            )
            return response.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def register_device(self, jwt_token, device_token, platform="ios", device_name="Local CIBA Demo"):
        """
        Registers a push device used for CIBA approval.

        - If client_id is set: uses tenant endpoint (/tenant/ciba/register-device)
        - If client_id is None: uses admin endpoint (/ciba/register-device)
        """
        if self.client_id:
            endpoint = f"{self.base_url}/authsec/uflow/auth/tenant/ciba/register-device"
        else:
            endpoint = f"{self.base_url}/authsec/uflow/auth/ciba/register-device"

        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json",
        }
        payload = {
            "device_token": device_token,
            "platform": platform,
            "device_name": device_name,
        }

        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                **_request_kwargs(self.base_url, timeout=10),
            )
            return response.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_pending_requests(self, jwt_token):
        """
        Lists pending CIBA requests for the authenticated tenant user.

        Tenant flow only.
        """
        if not self.client_id:
            return {"success": False, "error": "tenant_flow_required"}

        endpoint = f"{self.base_url}/authsec/uflow/auth/tenant/ciba/requests"
        headers = {"Authorization": f"Bearer {jwt_token}"}

        try:
            response = requests.get(
                endpoint,
                headers=headers,
                **_request_kwargs(self.base_url, timeout=10),
            )
            return response.json()
        except Exception as e:
            return {"success": False, "error": str(e), "requests": []}

    def respond_to_request(self, jwt_token, auth_req_id, approved=True, biometric_verified=True):
        """
        Approves or denies a pending CIBA request.

        - If client_id is set: uses tenant endpoint (/tenant/ciba/respond)
        - If client_id is None: uses admin endpoint (/ciba/respond)
        """
        if self.client_id:
            endpoint = f"{self.base_url}/authsec/uflow/auth/tenant/ciba/respond"
        else:
            endpoint = f"{self.base_url}/authsec/uflow/auth/ciba/respond"

        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json",
        }
        payload = {
            "auth_req_id": auth_req_id,
            "approved": approved,
            "biometric_verified": biometric_verified,
        }

        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                **_request_kwargs(self.base_url, timeout=10),
            )
            return response.json()
        except Exception as e:
            return {"success": False, "error": str(e)}
