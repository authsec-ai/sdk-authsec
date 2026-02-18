"""
AuthSec CIBA SDK - Passwordless Authentication for Voice Clients

Python SDK for integrating CIBA (Client-Initiated Backchannel Authentication) 
and TOTP verification into voice clients and other applications.

Supports both Admin and End-User (tenant) authentication flows:
- Admin flow: email only (original flow)
- Tenant flow: email + client_id (multi-client architecture)
"""

import requests
import time


class CIBAClient:
    """
    Python SDK for customers to integrate AuthSec into their own voice clients.
    Handles the technical execution of polling, verification, and initiation.
    
    Supports both Admin and End-User (tenant) authentication flows:
    - Admin flow: email only (original flow)
    - Tenant flow: email + client_id (multi-client architecture)
    
    Example usage:
        # Initialize for tenant flow
        from AuthSec_SDK import CIBAClient
        
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
            base_url: Optional base URL override. Defaults to production API.
        """
        self.base_url = base_url or "https://dev.api.authsec.dev"
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
            endpoint = f"{self.base_url}/uflow/auth/tenant/ciba/initiate"
            payload = {
                "client_id": self.client_id,
                "email": email,
                "binding_message": "Authentication requested via Voice SDK"
            }
        else:
            # Admin flow
            endpoint = f"{self.base_url}/uflow/auth/ciba/initiate"
            payload = {"login_hint": email, "binding_message": "Authentication requested via Voice SDK"}
        
        response = requests.post(endpoint, json=payload)
        return response.json()

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
            endpoint = f"{self.base_url}/uflow/auth/tenant/totp/login"
            payload = {"client_id": self.client_id, "email": email, "totp_code": code}
        else:
            # Admin flow (fallback to dev.api if base_url is localhost for compatibility)
            if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
                endpoint = "https://dev.api.authsec.dev/uflow/auth/totp/login"
            else:
                endpoint = f"{self.base_url}/uflow/auth/totp/login"
            payload = {"email": email, "totp_code": code}
        
        try:
            response = requests.post(endpoint, json=payload, timeout=10)
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
            endpoint = f"{self.base_url}/uflow/auth/tenant/ciba/token"
            payload = {"client_id": self.client_id, "auth_req_id": auth_req_id}
        else:
            # Admin flow
            endpoint = f"{self.base_url}/uflow/auth/ciba/token"
            payload = {"auth_req_id": auth_req_id}
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.active_polls.get(email) is True:
                return {"status": "cancelled"}
            response = requests.post(endpoint, json=payload)
            data = response.json()

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
