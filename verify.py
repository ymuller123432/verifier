from email_validator import validate_email, EmailNotValidError
import dns.resolver
import re

# Skip common free mailbox providers (as requested)
SKIP_PROVIDERS = {
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.co.uk", "ymail.com", "rocketmail.com",
    "aol.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com",
    "zoho.com", "gmx.com", "gmx.net", "mail.com",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "10minutemail.com",
    "tempmail.com",
}

# ✅ These are role-like inboxes you DO want to verify
ROLE_ALLOWED = {
    "ap",
    "finance",
    "payables",
    "accounting",
    "accountspayable",
    "invoice",
    "invoices",
}

# ⚠️ These are role accounts you may still want to flag as “role”
ROLE_BLOCKED = {
    "info", "support", "sales", "admin", "contact", "hello", "help",
    "billing", "accounts", "hr", "careers", "jobs",
    "noreply", "no-reply", "donotreply",
    "abuse", "postmaster", "webmaster",
}

def _clean_local(local: str) -> str:
    # accounts.payable -> accountspayable, accounts-payable -> accountspayable
    return re.sub(r"[^a-z0-9]", "", (local or "").lower())

def _resolver():
    r = dns.resolver.Resolver(configure=True)
    r.timeout = 1.5
    r.lifetime = 2.5
    return r

def has_mx(domain: str) -> bool:
    try:
        answers = _resolver().resolve(domain, "MX")
        return len(list(answers)) > 0
    except Exception:
        return False

def verify_quick(email: str) -> dict:
    email = (email or "").strip()
    if not email:
        return {"status": "invalid", "reason": "empty"}

    try:
        v = validate_email(email, check_deliverability=False)
        normalized = v.normalized
    except EmailNotValidError as e:
        return {"status": "invalid", "reason": str(e)}

    local, domain = normalized.rsplit("@", 1)
    domain_l = domain.lower()
    local_clean = _clean_local(local)

    # Skip free providers entirely
    if domain_l in SKIP_PROVIDERS:
        return {"status": "skipped", "reason": "free_provider_disabled", "email": normalized}

    # Disposable
    if domain_l in DISPOSABLE_DOMAINS:
        return {"status": "disposable", "reason": "disposable_domain", "email": normalized}

    # Role handling:
    # - allow AP/finance/payables/accounting/invoice etc
    # - flag other generic role accounts if you want
    if local_clean in ROLE_BLOCKED and local_clean not in ROLE_ALLOWED:
        return {"status": "role", "reason": "role_account", "email": normalized}

    # MX check (domain can receive mail)
    if not has_mx(domain_l):
        return {"status": "no_mx", "reason": "domain_no_mx", "email": normalized}

    # IMPORTANT: This still does NOT confirm mailbox exists; only syntax + MX.
    return {"status": "format_ok", "reason": "syntax_ok_mx_ok", "email": normalized}