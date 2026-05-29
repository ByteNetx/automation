import time
import requests

def get_access_token(TSG,client):
    """
        Generate an access token for SCM.
    """

    authURL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
    clientID = client['client_id']
    clientSECRET = client['client_credential']

    token_cache = {
        "access_token": None,
        "expires_at": 0
    }

    # Check if a token exists and is still valid (with a 60-second buffer for safety) 
    if token_cache["access_token"] and time.time() < token_cache["expires_at"] - 60:
        return token_cache["access_token"]
    else:
        # If no valid token, request a new one 
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        try:
            response = requests.post(
                authURL,
                headers=headers,
                data={
                    "grant_type": "client_credentials",
                    "client_id": clientID,
                    "client_secret": clientSECRET,
                    "scope": TSG
                }
            )

            # Raise an exception for 4xx or 5xx status codes 
            response.raise_for_status()

            token_data = response.json()
            token_cache["access_token"] = token_data["access_token"]

            # Calculate absolute expiration time: Current Time + lifetime of token 
            token_cache["expires_at"] = time.time() + token_data["expires_in"]

            return token_cache["access_token"]

        except requests.RequestException as e:
            print(f"Token retrieval failed: {e}")
            if e.response is not None:
                print(f"   Status: {e.response.status_code}, Body: {e.response.text}")

    return None
