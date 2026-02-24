from email_validator import validate_email, EmailNotValidError
import dns.resolver

ROLE_PREFIXES = {
    "info", "support", "sales", "admin", "contact", "hello", "billing", "accounts", "hr"
}

# Small starter list. You can expand this later.
DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "10minutemail.com",
    "tempmail.com",
}

def _resolver():
    r = dns.resolver.Resolver(configure=True)
    # Keep lookups snappy to avoid long hangs on weird DNS.
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
    local_l = local.lower()

    if domain_l in DISPOSABLE_DOMAINS:
        return {"status": "disposable", "reason": "disposable_domain", "email": normalized}

    if local_l in ROLE_PREFIXES:
        return {"status": "role", "reason": "role_account", "email": normalized}

    if not has_mx(domain_l):
        return {"status": "no_mx", "reason": "domain_no_mx", "email": normalized}

    return {"status": "valid", "reason": "syntax_ok_mx_ok", "email": normalized}
