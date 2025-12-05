# ZTS baza connector

Python client for interacting with baza.taborniki.si - the membership management system for Slovenian Scouts (Zveza tabornikov Slovenije).

## Features

- Automatic XSRF token management
- Session renewal before expiry
- Member search and creation
- Membership (clanarina) import for multiple members

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```python
from clanarina import TabornikiClient

# Initialize client (or use EMAIL and PASSWORD env vars)
client = TabornikiClient(
    email="your-email@example.com",
    password="your-password"
)

# Login
status = client.login()
if status != TabornikiClient.OK:
    print(f"Login failed: {client.last_error}")
    exit(1)

# Search for a member
status, member = client.search_member("Ime Priimek")
if status == TabornikiClient.OK:
    print(f"Found: {member['name']} {member['surname']} (#{member['number']})")

# Create a new member
status, member_number = client.create_member(
    name="Ime",
    surname="Priimek",
    sex="M",  # or "F"
    date_of_birth="2000-01-15",
    phone="+386 40 123 456",
    email="clan@example.com",
    address="Ulica 1",
    postal_code="1000"
)

# Import membership for existing members
status = client.import_membership([12345, 67890])

# Logout
client.logout()
```

## Status Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `OK` | Success |
| 1 | `ERR_LOGIN` | Login failed |
| 2 | `ERR_NOT_FOUND` | Member not found |
| 3 | `ERR_CREATE_FAILED` | Member creation failed |
| 4 | `ERR_IMPORT_FAILED` | Membership import failed |
| 5 | `ERR_NETWORK` | Network error |
| 6 | `ERR_INVALID_INPUT` | Invalid input |
| 7 | `ERR_SESSION` | Session error |
| 8 | `ERR_PERMISSION` | Permission denied |
| 9 | `ERR_UNKNOWN` | Unknown error |

## Environment Variables

- `EMAIL` - Login email
- `PASSWORD` - Login password
