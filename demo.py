#!/usr/bin/env python3
"""
Simple demo for using TabornikiClient from clanarina.py

STATUS CODES (from TabornikiClient):
    0  = Success (OK)
    1  = Login failed
    2  = Member not found
    3  = Member creation failed
    4  = Membership import failed
    5  = Network error
    6  = Invalid input
    7  = Session error
    8  = Permission denied
    9  = Unknown error
"""

from connector import TabornikiClient
from dotenv import load_dotenv
import os
load_dotenv()

# Create client with credentials
client = TabornikiClient(
    email=os.environ.get("CONNECTOR_EMAIL"),
    password=os.environ.get("CONNECTOR_PASSWORD")
)

# Login (returns status code, 0 = success)
status = client.login()
if status != 0:
    print(f"Login failed! Error: {client.last_error}")
    exit(1)

# ----- DEMO 1: Import membership for existing members -----
print("\n=== Import Membership Demo ===")
member_numbers = [2323, 23232] # Replace with actual member numbers from ROD
status = client.import_membership(member_numbers)
if status == 0:
    print("Import successful!")
else:
    print(f"Import failed (status {status}): {client.last_error}")

# ----- DEMO 2: Create a new member -----
print("\n=== Create Member Demo ===")
status, member_number = client.create_member(
    name="Janez",
    surname="Novak",
    sex="M",
    date_of_birth="2000-01-01",
    phone="+386 40 123 456",
    email="janez.novak@someemail.com",
    address="Glavna ulica 10",
    postal_code="5000"
)
if status == 0:
    print(f"Member created! Number: {member_number}")
else:
    print(f"Creation failed (status {status}): {client.last_error}")

# ----- DEMO 3: Search for a member -----
print("\n=== Search Member Demo ===")
status, member = client.search_member("Janez Novak")
if status == 0 and member:
    print(f"Found: {member['name']} {member['surname']} (#{member['number']})")
else:
    print(f"Search failed (status {status}): {client.last_error}")

# Logout when done
client.logout()
