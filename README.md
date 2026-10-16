# Secure Authentication Lab

A beginner-friendly local authentication API demonstrating password hashing, server-side input validation, rate limiting, secure cookie settings, logout, session expiry, generic login errors, and automated tests.

## Requirements
- Python 3.10 or newer
- pip

## Setup (Windows / VS Code)
1. Extract this project ZIP.
2. Open the extracted `secure_authentication_lab` folder in VS Code.
3. Open Terminal → New Terminal.
4. Create a virtual environment:
   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   ```
   If `py` is unavailable, try `python -m venv .venv`.
5. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
6. Run automated tests:
   ```powershell
   python -m pytest -q
   ```
7. Start the local app:
   ```powershell
   python app.py
   ```
8. The local service runs at `http://127.0.0.1:5000`. Keep the terminal open.

## Quick API examples
Use Postman, Thunder Client, or curl. Send JSON bodies with `Content-Type: application/json`.

Register:
```json
POST /register
{"username":"student_1","password":"correct horse battery"}
```
Login:
```json
POST /login
{"username":"student_1","password":"correct horse battery"}
```
View current user (after login, using the same cookie-enabled client):
```text
GET /me
```
Logout:
```text
POST /logout
```
Health check:
```text
GET /health
```

## Test output and evidence
Run `python -m pytest -q`. Save a screenshot of the terminal showing the passing test summary as evidence. The included `test_results.txt` records the test run from the project creation environment if available; always rerun tests on your own machine before submitting.

## Submission
Push the whole folder to a GitHub repository. Because the task requests a private-safe repository, set repository visibility to **Private** unless your task portal explicitly requires a public link. If the portal accepts a view-only link, share the repository with the intended reviewer or submit an approved read-only project link. Never publish real credentials or secrets.
