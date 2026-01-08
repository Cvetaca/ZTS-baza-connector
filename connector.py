#!/usr/bin/env python3
"""
Script for authenticating to baza.taborniki.si and managing membership requests.
Handles XSRF token management and automatic session renewal.

STATUS CODES:
    0  = Success
    1  = Login failed (invalid credentials or server error)
    2  = Member not found
    3  = Member creation failed
    4  = Membership import failed
    5  = Network error (connection failed, timeout, etc.)
    6  = Invalid input (missing required fields, wrong format)
    7  = Session error (could not establish or refresh session)
    8  = Permission denied (no access to group or action)
    9  = Unknown error
"""

import requests
import json
import logging
import os
import re
from urllib.parse import unquote
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("TabornikiClient")


class TabornikiClient:
    """Client for interacting with baza.taborniki.si"""

    BASE_URL = "https://baza.taborniki.si"
    LOGIN_URL = f"{BASE_URL}/login"
    DASHBOARD_URL = f"{BASE_URL}/dashboard"

    # Default session timeout (will be updated from cookie Max-Age during login)
    DEFAULT_SESSION_TIMEOUT = timedelta(hours=2)
    # Refresh session 10 minutes before expiry
    SESSION_REFRESH_BUFFER = timedelta(minutes=10)

    # Status codes
    OK = 0
    ERR_LOGIN = 1
    ERR_NOT_FOUND = 2
    ERR_CREATE_FAILED = 3
    ERR_IMPORT_FAILED = 4
    ERR_NETWORK = 5
    ERR_INVALID_INPUT = 6
    ERR_SESSION = 7
    ERR_PERMISSION = 8
    ERR_UNKNOWN = 9

    def __init__(self, email: str = None, password: str = None):
        """
        Initialize the client.

        Args:
            email: User email for login
            password: User password for login
        """
        self.email = email or os.environ.get("TABORNIKI_EMAIL")
        self.password = password or os.environ.get("TABORNIKI_PASSWORD")

        self.session = requests.Session()
        self.session_expiry = None
        self.session_timeout = self.DEFAULT_SESSION_TIMEOUT  # Will be updated from cookie
        self.is_authenticated = False
        self.group_id = None  # Will be set during login
        self.last_error = None  # Store last error message

        # Set up default headers to mimic browser
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "Accept": "text/html, application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "keep-alive",
        })

    def _get_xsrf_token(self) -> str:
        """
        Get the XSRF token from cookies.
        The token is URL-encoded in the cookie, so we need to decode it.

        Returns:
            The decoded XSRF token
        """
        xsrf_cookie = self.session.cookies.get("XSRF-TOKEN")
        if xsrf_cookie:
            return unquote(xsrf_cookie)
        return None

    def _update_session_expiry(self):
        """Update the session expiry time based on current time."""
        self.session_expiry = datetime.now() + self.session_timeout

    def _parse_session_timeout_from_response(self, response):
        """
        Parse the Max-Age value from Set-Cookie headers to determine session timeout.

        Args:
            response: The HTTP response object

        Returns:
            timedelta or None if Max-Age could not be parsed
        """
        # Look for Max-Age in Set-Cookie headers
        set_cookie_headers = response.headers.get("Set-Cookie", "")

        # Also check raw headers if available (for multiple Set-Cookie headers)
        if hasattr(response, 'raw') and hasattr(response.raw, 'headers'):
            # Get all Set-Cookie headers
            all_cookies = response.raw.headers.getlist('Set-Cookie')
            if all_cookies:
                set_cookie_headers = "; ".join(all_cookies)

        # Parse Max-Age from the cookie string
        max_age_match = re.search(r'Max-Age=(\d+)', set_cookie_headers, re.IGNORECASE)
        if max_age_match:
            max_age_seconds = int(max_age_match.group(1))
            timeout = timedelta(seconds=max_age_seconds)
            logger.debug(f"Parsed session timeout from cookie: {max_age_seconds} seconds")
            return timeout

        return None

    def _is_session_valid(self) -> bool:
        """
        Check if the current session is still valid.

        Returns:
            True if session is valid, False otherwise
        """
        if not self.is_authenticated or not self.session_expiry:
            return False

        # Check if session will expire soon
        return datetime.now() < (self.session_expiry - self.SESSION_REFRESH_BUFFER)

    def _ensure_authenticated(self):
        """
        Ensure we have a valid authenticated session.
        Automatically re-authenticates if session is expired or about to expire.

        Returns:
            Status code (0 = OK, 7 = session error)
        """
        if not self._is_session_valid():
            logger.info("Session expired or not authenticated. Logging in...")
            return self.login()
        return self.OK

    def _fetch_initial_tokens(self):
        """
        Fetch the login page to get initial XSRF token and session cookie.
        This is necessary before making the login POST request.

        Returns:
            Status code (0 = OK, 5 = network error, 7 = session error)
        """
        logger.debug("Fetching initial tokens...")
        try:
            response = self.session.get(self.LOGIN_URL, timeout=30)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.last_error = f"Network error fetching tokens: {e}"
            logger.error(self.last_error)
            return self.ERR_NETWORK

        # Verify we got the XSRF token
        if not self._get_xsrf_token():
            self.last_error = "Failed to obtain XSRF token from login page"
            logger.error(self.last_error)
            return self.ERR_SESSION

        logger.debug("Initial tokens obtained successfully")
        return self.OK

    def login(self):
        """
        Perform login to the website.

        Returns:
            Status code (0 = OK, 1 = login failed, 5 = network error, 6 = invalid input)
        """
        if not self.email or not self.password:
            self.last_error = "Email and password are required"
            logger.error(self.last_error)
            return self.ERR_INVALID_INPUT

        # First, get the initial tokens
        status = self._fetch_initial_tokens()
        if status != self.OK:
            return status

        # Prepare login request headers (Inertia.js specific)
        xsrf_token = self._get_xsrf_token()
        headers = {
            "Content-Type": "application/json",
            "Origin": self.BASE_URL,
            "Referer": self.LOGIN_URL,
            "X-Inertia": "true",
            "X-Inertia-Version": "ee0ee8477b08a97e13d1494194e001e0",
            "X-Requested-With": "XMLHttpRequest",
            "X-XSRF-TOKEN": xsrf_token,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }

        # Login payload
        payload = {
            "email": self.email,
            "password": self.password,
            "remember": False
        }

        logger.info(f"Attempting login for {self.email}...")

        try:
            # Make login request
            response = self.session.post(
                self.LOGIN_URL,
                json=payload,
                headers=headers,
                allow_redirects=False,
                timeout=30
            )
        except requests.exceptions.RequestException as e:
            self.last_error = f"Network error during login: {e}"
            logger.error(self.last_error)
            return self.ERR_NETWORK

        # Check for successful login (302 redirect to dashboard)
        if response.status_code == 302:
            location = response.headers.get("Location", "")
            if "dashboard" in location or location == self.DASHBOARD_URL:
                self.is_authenticated = True
                # Update session timeout from cookie Max-Age if available
                parsed_timeout = self._parse_session_timeout_from_response(response)
                if parsed_timeout:
                    self.session_timeout = parsed_timeout
                    logger.info(f"Session timeout set to {parsed_timeout.total_seconds()} seconds from cookie")
                self._update_session_expiry()
                self._fetch_group_access()
                logger.info("Login successful!")
                return self.OK

        # Check for Inertia response (sometimes login returns 200 with redirect info)
        if response.status_code == 200:
            try:
                data = response.json()
                if data.get("component") == "Dashboard" or "props" in data:
                    self.is_authenticated = True
                    # Update session timeout from cookie Max-Age if available
                    parsed_timeout = self._parse_session_timeout_from_response(response)
                    if parsed_timeout:
                        self.session_timeout = parsed_timeout
                        logger.info(f"Session timeout set to {parsed_timeout.total_seconds()} seconds from cookie")
                    self._update_session_expiry()
                    self._fetch_group_access()
                    logger.info("Login successful!")
                    return self.OK
            except json.JSONDecodeError:
                pass

        # Login failed
        self.last_error = f"Login failed with status code: {response.status_code}"
        logger.error(self.last_error)
        return self.ERR_LOGIN

    def _make_request(self, method, url, **kwargs):
        """
        Make an authenticated request with automatic session renewal.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: URL to request
            **kwargs: Additional arguments passed to requests

        Returns:
            Tuple of (status_code, response or None)
        """
        auth_status = self._ensure_authenticated()
        if auth_status != self.OK:
            return auth_status, None

        # Add XSRF token to headers
        xsrf_token = self._get_xsrf_token()
        headers = kwargs.pop("headers", {})
        headers.update({
            "X-XSRF-TOKEN": xsrf_token,
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.BASE_URL,
            "Referer": self.DASHBOARD_URL,
        })

        # Check if allow_redirects was explicitly set
        allow_redirects = kwargs.get("allow_redirects", True)

        # Set default timeout
        if "timeout" not in kwargs:
            kwargs["timeout"] = 30

        try:
            # Make the request
            response = self.session.request(method, url, headers=headers, **kwargs)
        except requests.exceptions.RequestException as e:
            self.last_error = f"Network error: {e}"
            logger.error(self.last_error)
            return self.ERR_NETWORK, None

        # Update session expiry on successful request
        if response.ok or response.status_code == 302:
            self._update_session_expiry()

        # Check if we got a redirect to login (session expired server-side)
        if response.status_code in (401, 403) or (
            response.status_code == 302 and "login" in response.headers.get("Location", "") and allow_redirects
        ):
            logger.info("Session expired server-side, re-authenticating...")
            self.is_authenticated = False
            auth_status = self._ensure_authenticated()
            if auth_status != self.OK:
                return auth_status, None

            # Retry the request
            try:
                xsrf_token = self._get_xsrf_token()
                headers["X-XSRF-TOKEN"] = xsrf_token
                response = self.session.request(method, url, headers=headers, **kwargs)
            except requests.exceptions.RequestException as e:
                self.last_error = f"Network error on retry: {e}"
                logger.error(self.last_error)
                return self.ERR_NETWORK, None

        return self.OK, response

    def _fetch_group_access(self):
        """
        Fetch the group_access ID by making a GET request to /members/create.
        This should be called after successful login.

        Returns:
            Status code (0 = OK, 5 = network error, 8 = permission denied)
        """
        url = f"{self.BASE_URL}/members/create"

        headers = {
            "Accept": "text/html, application/xhtml+xml, application/json",
            "X-Inertia": "true",
            "X-Inertia-Version": "ee0ee8477b08a97e13d1494194e001e0",
            "X-XSRF-TOKEN": self._get_xsrf_token(),
            "X-Requested-With": "XMLHttpRequest",
        }

        logger.debug("Fetching group access...")

        try:
            response = self.session.get(url, headers=headers, timeout=30)
        except requests.exceptions.RequestException as e:
            self.last_error = f"Network error fetching group access: {e}"
            logger.error(self.last_error)
            return self.ERR_NETWORK

        if response.status_code == 200:
            try:
                data = response.json()
                group_access = data.get("props", {}).get("auth", {}).get("user", {}).get("group_access")
                if group_access:
                    self.group_id = group_access
                    group_name = data.get("props", {}).get("group", {}).get("name", "Unknown")
                    logger.info(f"Group access obtained: {group_name} ({self.group_id})")
                    return self.OK
                else:
                    self.last_error = "Could not find group_access in response"
                    logger.warning(self.last_error)
                    return self.ERR_PERMISSION
            except json.JSONDecodeError:
                self.last_error = "Could not parse group access response"
                logger.warning(self.last_error)
                return self.ERR_UNKNOWN
        else:
            self.last_error = f"Failed to fetch group access (status {response.status_code})"
            logger.warning(self.last_error)
            return self.ERR_PERMISSION

    def get(self, url, **kwargs):
        """Make an authenticated GET request."""
        return self._make_request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        """Make an authenticated POST request."""
        return self._make_request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        """Make an authenticated PUT request."""
        return self._make_request("PUT", url, **kwargs)

    def delete(self, url, **kwargs):
        """Make an authenticated DELETE request."""
        return self._make_request("DELETE", url, **kwargs)

    def update_membership(self, member_id, data=None):
        """
        Update membership for a specific member.

        Args:
            member_id: The UUID of the member
            data: Optional data to send with the request

        Returns:
            Status code (0 = OK, others = error)
        """
        url = f"{self.BASE_URL}/members/{member_id}/membership"

        headers = {
            "Content-Type": "application/json",
            "Accept": "text/html, application/xhtml+xml, application/json",
            "X-Inertia": "true",
            "X-Inertia-Version": "ee0ee8477b08a97e13d1494194e001e0",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }

        logger.debug(f"Updating membership for member: {member_id}")

        if data:
            status, response = self.post(url, json=data, headers=headers)
        else:
            status, response = self.post(url, headers=headers)

        if status != self.OK:
            return status

        logger.debug(f"Response status: {response.status_code}")
        return self.OK

    def get_members_by_numbers(self, member_numbers):
        """
        Get member details by their member numbers.

        Args:
            member_numbers: List of member numbers (e.g., [24824, 26087])

        Returns:
            Tuple of (status_code, list of member dicts or None)
        """
        if not member_numbers:
            self.last_error = "No member numbers provided"
            logger.error(self.last_error)
            return self.ERR_INVALID_INPUT, None

        # Build query string with member_ids[0]=..., member_ids[1]=..., etc.
        params = {f"member_ids[{i}]": num for i, num in enumerate(member_numbers)}

        url = f"{self.BASE_URL}/api/members"

        logger.debug(f"Fetching member details for {len(member_numbers)} members...")

        status, response = self.get(url, params=params)
        if status != self.OK:
            return status, None

        if not response.ok:
            self.last_error = f"Failed to fetch members (status {response.status_code})"
            logger.error(self.last_error)
            return self.ERR_NOT_FOUND, None

        try:
            members = response.json()
            logger.debug(f"Retrieved {len(members)} members")
            return self.OK, members
        except json.JSONDecodeError:
            self.last_error = "Failed to parse members response"
            logger.error(self.last_error)
            return self.ERR_UNKNOWN, None

    def import_membership(self, member_numbers):
        """
        Import membership for multiple members by their member numbers.

        This function:
        1. Converts member numbers to UUIDs via the API
        2. Sends a POST request to import membership for those members

        Args:
            member_numbers: List of member numbers (e.g., [24824, 26087])

        Returns:
            Status code (0 = OK, 2 = not found, 4 = import failed, others = error)
        """
        # Step 1: Get member UUIDs from member numbers
        status, members = self.get_members_by_numbers(member_numbers)
        if status != self.OK:
            return status

        if not members:
            self.last_error = "No members found for the provided member numbers"
            logger.error(self.last_error)
            return self.ERR_NOT_FOUND

        # Extract UUIDs from the response
        member_ids = [member["id"] for member in members]

        logger.info(f"Resolved {len(member_ids)} member UUIDs:")
        for member in members:
            logger.info(f"  - {member['number']}: {member['name']} {member['surname']} -> {member['id']}")

        # Step 2: Make the import POST request
        url = f"{self.BASE_URL}/membership/import"

        headers = {
            "Content-Type": "application/json",
            "Accept": "text/html, application/xhtml+xml, application/json",
            "X-Inertia": "true",
            "X-Inertia-Version": "ee0ee8477b08a97e13d1494194e001e0",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }

        payload = {"member_ids": member_ids}

        logger.info(f"Importing membership for {len(member_ids)} members...")

        status, response = self.post(url, json=payload, headers=headers)
        if status != self.OK:
            return status

        if response.status_code in (200, 302):
            logger.info(f"Import successful (status {response.status_code})")
            return self.OK
        else:
            self.last_error = f"Import failed with status {response.status_code}"
            logger.error(self.last_error)
            return self.ERR_IMPORT_FAILED

    def search_member(self, query, date_of_birth=None):
        """
        Search for a member by name/surname.

        Args:
            query: Search query (e.g., "Name Surname")
            date_of_birth: Optional date of birth to match (format: YYYY-MM-DD)

        Returns:
            Tuple of (status_code, member dict or None)
        """
        url = f"{self.BASE_URL}/members"

        headers = {
            "Accept": "text/html, application/xhtml+xml, application/json",
            "X-Inertia": "true",
            "X-Inertia-Version": "ee0ee8477b08a97e13d1494194e001e0",
        }

        params = {"filter[q]": query}

        logger.debug(f"Searching for member: {query}")
        status, response = self.get(url, params=params, headers=headers)

        if status != self.OK:
            return status, None

        if response.status_code != 200:
            self.last_error = f"Search failed with status {response.status_code}"
            logger.error(self.last_error)
            return self.ERR_NOT_FOUND, None

        try:
            data = response.json()
            members = data.get("props", {}).get("items", {}).get("data", [])

            if not members:
                self.last_error = "No members found"
                logger.debug(self.last_error)
                return self.ERR_NOT_FOUND, None

            if len(members) == 1:
                return self.OK, members[0]

            # Multiple members found - match by date_of_birth if provided

            if date_of_birth:
                for member in members:
                    if member.get("date_of_birth") == date_of_birth:
                        return self.OK, member
                logger.warning(f"Multiple members found but none match date_of_birth {date_of_birth}")

            # Return first match if no date_of_birth filter or no match
            logger.warning(f"Multiple members found ({len(members)}), returning first match")
            return self.OK, members[0]

        except json.JSONDecodeError:
            self.last_error = "Failed to parse search response"
            logger.error(self.last_error)
            return self.ERR_UNKNOWN, None

    def create_member(
        self,
        name,
        surname,
        sex,
        date_of_birth,
        phone,
        email,
        address,
        postal_code,
        joined_at=None,
        note="",
        additional_contacts=None,
        magazine_subscription=True
    ):
        """
        Create a new member in the database.

        Args:
            name: First name
            surname: Last name
            sex: "M" or "F" or "O"
            date_of_birth: Date of birth (format: YYYY-MM-DD)
            phone: Phone number (e.g., "+386 12345678")
            email: Email address
            address: Street address
            postal_code: Postal code
            joined_at: Date joined (format: YYYY-MM-DD), defaults to today
            note: Optional note
            additional_contacts: List of additional contacts (default: [])
            magazine_subscription: Whether to subscribe to magazine (default: True)

        Returns:
            Tuple of (status_code, member_number or None)
        """
        if not self.group_id:
            self.last_error = "Group ID not set. Make sure login was successful."
            logger.error(self.last_error)
            return self.ERR_PERMISSION, None

        # Validate required fields
        if not all([name, surname, sex, date_of_birth, address, postal_code]):
            self.last_error = "Missing required fields"
            logger.error(self.last_error)
            return self.ERR_INVALID_INPUT, None

        if joined_at is None:
            joined_at = datetime.now().strftime("%Y-%m-%d")

        if additional_contacts is None:
            additional_contacts = []

        url = f"{self.BASE_URL}/members"

        headers = {
            "Content-Type": "application/json",
            "Accept": "text/html, application/xhtml+xml, application/json",
            "X-Inertia": "true",
            "X-Inertia-Version": "ee0ee8477b08a97e13d1494194e001e0",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }

        payload = {
            "group_id": self.group_id,
            "name": name,
            "surname": surname,
            "sex": sex,
            "date_of_birth": date_of_birth,
            "phone": phone or "",
            "email": email or "",
            "address": address,
            "postal_code": postal_code,
            "joined_at": joined_at,
            "note": note,
            "additional_contacts": additional_contacts,
            "magazine_subscription": magazine_subscription
        }

        logger.info(f"Creating member: {name} {surname}")

        status, response = self.post(url, json=payload, headers=headers, allow_redirects=False)

        if status != self.OK:
            return status, None

        # Check for successful creation (302 redirect)
        if response.status_code == 302:
            location = response.headers.get("Location", "")
            logger.debug(f"Member creation redirect to: {location}")
            if "/members" in location or "/dashboard" in location:
                logger.info("Member created successfully!")

                # Search for the newly created member to get their number
                search_query = f"{name} {surname}"
                search_status, member = self.search_member(search_query, date_of_birth)

                if search_status == self.OK and member:
                    member_number = member.get("number")
                    logger.info(f"Member number: {member_number}")
                    return self.OK, member_number
                else:
                    logger.warning("Member created but could not retrieve member number")
                    return self.OK, None

        self.last_error = f"Failed to create member (status {response.status_code})"
        logger.error(self.last_error)

        try:
            error_data = response.json()
            logger.debug(f"Error response: {json.dumps(error_data)}")
        except json.JSONDecodeError:
            pass

        return self.ERR_CREATE_FAILED, None

    def logout(self):
        """Logout and clear session."""
        try:
            self.post(f"{self.BASE_URL}/logout")
        except Exception:
            pass
        finally:
            self.is_authenticated = False
            self.session_expiry = None
            self.session_timeout = self.DEFAULT_SESSION_TIMEOUT
            self.group_id = None
            self.session.cookies.clear()
            logger.info("Logged out successfully")


def main():
    """Main function demonstrating usage."""
    client = TabornikiClient(
        email=os.environ.get("CONNECTOR_EMAIL"),
        password=os.environ.get("CONNECTOR_PASSWORD")
    )

    # Login
    status = client.login()
    if status != TabornikiClient.OK:
        logger.error(f"Login failed with status {status}: {client.last_error}")
        return

    try:
        while True:
            choice = input("1 for import membership, 2 for new member creation: ")
            if choice == "2":
                status, member_number = client.create_member(
                    name="Demo",
                    surname="User",
                    sex="M",
                    date_of_birth="2024-11-01",
                    phone="+386 11111",
                    email="uporabnik@posta.si",
                    address="Test ulica 15",
                    postal_code="5000"
                )
                if status == TabornikiClient.OK:
                    print(f"New member number: {member_number}")
                else:
                    print(f"Failed to create member (status {status}): {client.last_error}")
            else:
                member_numbers = input("Enter ZTS numbers to import (comma-separated): ")
                member_numbers = [int(num.strip()) for num in member_numbers.split(",") if num.strip().isdigit()]
                status = client.import_membership(member_numbers)
                if status == TabornikiClient.OK:
                    print("Membership import successful!")
                else:
                    print(f"Import failed (status {status}): {client.last_error}")
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        client.logout()


if __name__ == "__main__":
    main()
