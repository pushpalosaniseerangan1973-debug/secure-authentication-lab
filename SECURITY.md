# Authentication Security Note

## Controls implemented in this educational lab
- Passwords are stored as Werkzeug scrypt password hashes, never as plaintext.
- Registration validates username and password length/type on the server.
- Login returns a generic error for unknown users and incorrect passwords.
- Login failures are rate-limited to five attempts per username key per 60-second window.
- Successful login clears the prior session before setting the authenticated username.
- Sessions are marked permanent with a 15-minute lifetime.
- Session cookies use HttpOnly and SameSite=Lax; Secure can be enabled with `COOKIE_SECURE=1`.
- Logout clears the session and expires the session cookie.
- Basic response headers reduce MIME sniffing, framing, caching of sensitive responses, and referrer leakage.
- Automated tests cover these behaviors.

## Important limitations
This is a local teaching example, not a production-ready identity service.
- Users and rate-limit counters are in-memory and disappear on restart. Multiple workers would not share the rate limit.
- Flask's signed client-side session is not an opaque server-side session store. Do not store secrets in it.
- The development default secret key is not safe for deployment. Set a strong random `SECRET_KEY`.
- `COOKIE_SECURE=1` requires HTTPS; it is left off by default for local HTTP testing.
- The rate limiter keys by username and can be abused to temporarily block a victim's username. Production systems need carefully designed IP/account/device controls, monitoring, and recovery.
- CSRF protection must be added if this service is used with browser cookies and state-changing routes in a real deployment.
- Use a production WSGI server, TLS, a persistent database, secret management, monitoring, and a reviewed account-recovery flow before deployment.

## Authorized use
Run and test this service locally or in an environment you own or are explicitly authorized to assess.
