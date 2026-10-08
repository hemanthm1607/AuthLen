# AuthLens — Test Categories Reference

This document defines what each testing module checks and why it matters.

---

## 🔐 Security (`testing-engine/security/`)

| Check ID | What It Tests | Why It Matters |
|----------|---------------|----------------|
| SEC-001 | Rate limiting on login endpoint | Prevents brute-force attacks |
| SEC-002 | Account lockout after N failed attempts | Stops credential stuffing |
| SEC-003 | CSRF token presence on login form | Prevents cross-site request forgery |
| SEC-004 | Session cookie flags (HttpOnly, Secure, SameSite) | Prevents session hijacking |
| SEC-005 | Password transmitted over HTTPS | Prevents credential sniffing |
| SEC-006 | Verbose error messages (user vs. password) | Prevents username enumeration |

---

## 🖱️ Usability (`testing-engine/usability/`)

| Check ID | What It Tests | Why It Matters |
|----------|---------------|----------------|
| USE-001 | Password visibility toggle present | Users can verify what they typed |
| USE-002 | Clear, human-readable error messages | Users know how to fix mistakes |
| USE-003 | "Remember me" option | Reduces friction for returning users |
| USE-004 | Auto-focus on first field on page load | Faster interaction |
| USE-005 | Loading state shown during submission | Users know the app is working |

---

## ♿ Accessibility (`testing-engine/accessibility/`)

| Check ID | What It Tests | Why It Matters |
|----------|---------------|----------------|
| A11Y-001 | All form inputs have associated `<label>` elements | Screen reader compatibility |
| A11Y-002 | Keyboard-only navigation through the form | Motor disability support |
| A11Y-003 | ARIA roles and attributes on interactive elements | Assistive technology support |
| A11Y-004 | Sufficient color contrast on text and inputs | Low vision support |
| A11Y-005 | Error messages announced to screen readers | WCAG 2.1 AA compliance |

---

## 🔑 Account Recovery (`testing-engine/recovery/`)

| Check ID | What It Tests | Why It Matters |
|----------|---------------|----------------|
| REC-001 | "Forgot password" link present and functional | Users can recover access |
| REC-002 | Password reset token expiry enforced | Stale tokens are a security risk |
| REC-003 | Reset link is single-use | Replay attack prevention |
| REC-004 | Account lockout can be manually unlocked | Prevents permanent DoS |
| REC-005 | Recovery email not enumerable | Prevents user discovery |

---

## Result Severity Levels

| Level    | Meaning |
|----------|---------|
| `HIGH`   | Exploitable vulnerability — fix before launch |
| `MEDIUM` | Significant friction or risk — fix soon |
| `LOW`    | Minor improvement — fix when possible |
| `INFO`   | Best practice suggestion |
