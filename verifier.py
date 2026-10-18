"""
Email Verification Engine:
Implements the full 5-stage verification pipeline:
1. Syntax & Format Validation (RFC 5322)
2. Domain & DNS / MX Records Check
3. Disposable & Role-Based Detection
4. Catch-All (Accept-All) Mail Server Detection
5. SMTP Handshake Simulation (HELO -> MAIL FROM -> RCPT TO -> QUIT)
"""

import re
import socket
import smtplib
import uuid
from typing import List, Dict, Optional, Tuple
import dns.resolver

from disposable_domains import DISPOSABLE_DOMAINS, ROLE_ACCOUNTS


# RFC 5322 compliant regex for basic email syntax
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


class VerificationStatus:
    VALID = "VALID"
    INVALID = "INVALID"
    CATCH_ALL = "CATCH_ALL"
    RISKY = "RISKY"
    DISPOSABLE = "DISPOSABLE"
    UNKNOWN = "UNKNOWN"
    SMTP_UNREACHABLE = "SMTP_UNREACHABLE"


class EmailVerifier:
    def __init__(self, smtp_timeout: float = 6.0, sender_email: str = "verify@mailcheck-probe.com"):
        self.smtp_timeout = smtp_timeout
        self.sender_email = sender_email
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 5.0
        # Cache domain MX lookups & catch-all checks during batch verification
        self._mx_cache: Dict[str, List[str]] = {}
        self._catch_all_cache: Dict[str, Optional[bool]] = {}
        self._smtp_port_accessible: Optional[bool] = None

    # ==========================================
    # Step 1: Syntax & Format Validation
    # ==========================================
    @staticmethod
    def validate_syntax(email: str) -> Tuple[bool, str]:
        """
        Validates syntax against RFC 5322 constraints.
        Checks length limits, symbols, and consecutive dots.
        """
        if not email or not isinstance(email, str):
            return False, "Email cannot be empty."

        email = email.strip()
        if len(email) > 254:
            return False, "Email length exceeds RFC 254-character maximum."

        parts = email.split("@")
        if len(parts) != 2:
            return False, "Email must contain exactly one '@' symbol."

        local_part, domain_part = parts[0], parts[1]

        if not local_part or len(local_part) > 64:
            return False, "Local part must be between 1 and 64 characters."

        if not domain_part or len(domain_part) > 253:
            return False, "Domain part must be between 1 and 253 characters."

        if local_part.startswith(".") or local_part.endswith("."):
            return False, "Local part cannot begin or end with a period."

        if ".." in local_part or ".." in domain_part:
            return False, "Email cannot contain consecutive periods ('..')."

        if not EMAIL_REGEX.match(email):
            return False, "Email failed RFC 5322 syntax validation."

        if "." not in domain_part:
            return False, "Domain must contain a valid top-level domain (TLD)."

        return True, "Valid RFC 5322 syntax."

    # ==========================================
    # Step 2: Domain & DNS MX Records Check
    # ==========================================
    def get_mx_records(self, domain: str) -> Tuple[List[str], str]:
        """
        Performs DNS MX lookup, returning mail exchangers ordered by priority.
        Falls back to 'A' record according to RFC 5321 if no MX exists.
        """
        domain = domain.strip().lower()
        if domain in self._mx_cache:
            return self._mx_cache[domain], "Cached MX records retrieved."

        try:
            answers = self.resolver.resolve(domain, "MX")
            # Sort by priority (lowest preference number first)
            sorted_mx = sorted(answers, key=lambda record: record.preference)
            mx_hosts = [str(r.exchange).rstrip(".") for r in sorted_mx]
            self._mx_cache[domain] = mx_hosts
            return mx_hosts, f"Found {len(mx_hosts)} MX server(s)."
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Fallback to A record per RFC 5321
            try:
                a_answers = self.resolver.resolve(domain, "A")
                if a_answers:
                    self._mx_cache[domain] = [domain]
                    return [domain], "No MX records found; fallback to domain A record."
            except Exception:
                pass
            return [], f"Domain '{domain}' does not exist or has no active mail servers."
        except Exception as e:
            return [], f"DNS lookup failed for '{domain}': {str(e)}"

    # ==========================================
    # Step 3: Disposable & Role-Based Check
    # ==========================================
    @staticmethod
    def check_disposable_and_role(email: str) -> Dict[str, bool]:
        """
        Checks if the address is a disposable burner or generic role account.
        """
        parts = email.lower().split("@")
        local_part = parts[0]
        domain_part = parts[1] if len(parts) > 1 else ""

        is_disposable = domain_part in DISPOSABLE_DOMAINS
        is_role = local_part in ROLE_ACCOUNTS

        return {
            "is_disposable": is_disposable,
            "is_role": is_role,
        }

    # ==========================================
    # Pre-flight Check: Is Port 25 reachable?
    # ==========================================
    def is_port_25_blocked(self, mx_host: str) -> bool:
        """
        Tests if outbound port 25 is open or blocked by the local ISP/network.
        """
        if self._smtp_port_accessible is not None:
            return not self._smtp_port_accessible

        try:
            with socket.create_connection((mx_host, 25), timeout=self.smtp_timeout):
                self._smtp_port_accessible = True
                return False
        except (socket.timeout, ConnectionRefusedError, OSError):
            self._smtp_port_accessible = False
            return True

    # ==========================================
    # Step 4: Catch-All (Accept-All) Detection
    # ==========================================
    def check_catch_all(self, domain: str, mx_host: str) -> Tuple[Optional[bool], str]:
        """
        Tests if the mail server accepts any non-existent email (Catch-All).
        Sends probe with a random GUID mailbox.
        """
        domain = domain.lower()
        if domain in self._catch_all_cache:
            is_ca = self._catch_all_cache[domain]
            return is_ca, "Catch-all cached result."

        if self.is_port_25_blocked(mx_host):
            self._catch_all_cache[domain] = None
            return None, "Port 25 blocked by ISP; cannot probe catch-all."

        # Generate a random non-existent test address
        random_str = "probe_test_" + uuid.uuid4().hex[:12]
        fake_email = f"{random_str}@{domain}"

        try:
            smtp = smtplib.SMTP(timeout=self.smtp_timeout)
            smtp.connect(mx_host, 25)
            smtp.helo("mailverifier.local")
            smtp.mail(self.sender_email)
            code, msg = smtp.rcpt(fake_email)
            smtp.quit()

            if code == 250:
                self._catch_all_cache[domain] = True
                return True, "Domain is Catch-All (Server accepts all random addresses)."
            else:
                self._catch_all_cache[domain] = False
                return False, "Domain rejects non-existent mailboxes (Not Catch-All)."
        except Exception as e:
            self._catch_all_cache[domain] = None
            return None, f"SMTP handshake during catch-all check failed: {str(e)}"

    # ==========================================
    # Step 5: SMTP Handshake Probe (RCPT TO)
    # ==========================================
    def verify_single_smtp(self, email: str, mx_host: str) -> Tuple[int, str]:
        """
        Connects via SMTP, performs HELO -> MAIL FROM -> RCPT TO, and terminates with QUIT.
        Does NOT send DATA or any email body.
        """
        try:
            smtp = smtplib.SMTP(timeout=self.smtp_timeout)
            smtp.connect(mx_host, 25)
            smtp.helo("mailverifier.local")
            smtp.mail(self.sender_email)
            code, response = smtp.rcpt(email)
            try:
                smtp.quit()
            except Exception:
                pass
            msg = response.decode("utf-8", errors="ignore") if isinstance(response, bytes) else str(response)
            return code, msg
        except socket.timeout:
            return -1, "Connection timed out (Port 25 blocked or server silent)."
        except Exception as e:
            return -2, f"SMTP error: {str(e)}"

    # ==========================================
    # Complete Pipeline Verification for an Email
    # ==========================================
    def verify(self, email: str) -> Dict:
        """
        Runs the full 5-stage verification pipeline for an email address.
        """
        result = {
            "email": email,
            "status": VerificationStatus.UNKNOWN,
            "details": [],
            "syntax_valid": False,
            "mx_records": [],
            "is_disposable": False,
            "is_role": False,
            "is_catch_all": None,
            "smtp_code": None,
            "smtp_message": "",
            "confidence": 0,
            "notes": ""
        }

        # 1. Syntax Check
        syntax_ok, syntax_msg = self.validate_syntax(email)
        result["syntax_valid"] = syntax_ok
        result["details"].append(f"[Step 1: Syntax] {syntax_msg}")
        if not syntax_ok:
            result["status"] = VerificationStatus.INVALID
            result["confidence"] = 0
            result["notes"] = "Failed syntax check."
            return result

        domain = email.split("@")[1]

        # 2. DNS MX Check
        mx_hosts, mx_msg = self.get_mx_records(domain)
        result["mx_records"] = mx_hosts
        result["details"].append(f"[Step 2: DNS MX] {mx_msg}")
        if not mx_hosts:
            result["status"] = VerificationStatus.INVALID
            result["confidence"] = 0
            result["notes"] = "Domain has no valid MX or mail records."
            return result

        # 3. Disposable & Role-based Check
        disposable_role = self.check_disposable_and_role(email)
        result["is_disposable"] = disposable_role["is_disposable"]
        result["is_role"] = disposable_role["is_role"]

        if result["is_disposable"]:
            result["status"] = VerificationStatus.DISPOSABLE
            result["confidence"] = 0
            result["details"].append("[Step 3: Reputational] Domain is a known disposable burner email provider.")
            result["notes"] = "Disposable email address."
            return result

        if result["is_role"]:
            result["details"].append("[Step 3: Reputational] Address is a generic role account (e.g., info@, admin@).")

        # 4. Catch-All & Port 25 Check
        primary_mx = mx_hosts[0]
        port_blocked = self.is_port_25_blocked(primary_mx)

        if port_blocked:
            result["status"] = VerificationStatus.SMTP_UNREACHABLE
            result["details"].append("[Step 4: Network] Outbound Port 25 is filtered/blocked by your local ISP.")
            result["details"].append("[Step 5: SMTP Handshake] Skipped direct SMTP test due to ISP port 25 restriction.")
            result["confidence"] = 65  # DNS & MX verified, but cannot ping individual mailbox locally
            result["notes"] = "DNS & MX verified. SMTP handshake unavailable due to local ISP port 25 filter."
            return result

        # Check catch-all
        is_catch_all, ca_msg = self.check_catch_all(domain, primary_mx)
        result["is_catch_all"] = is_catch_all
        result["details"].append(f"[Step 4: Catch-All] {ca_msg}")

        # 5. SMTP Handshake
        code, msg = self.verify_single_smtp(email, primary_mx)
        result["smtp_code"] = code
        result["smtp_message"] = msg
        result["details"].append(f"[Step 5: SMTP Handshake] Server returned code {code}: {msg}")

        if is_catch_all:
            result["status"] = VerificationStatus.CATCH_ALL
            result["confidence"] = 55
            result["notes"] = "Domain is Catch-All. Mail server accepts all addresses; delivery cannot be 100% verified via SMTP."
        elif code == 250:
            result["status"] = VerificationStatus.VALID
            result["confidence"] = 98
            result["notes"] = "Mailbox verified: SMTP server confirmed recipient exists (250 OK)."
        elif code in (550, 551, 552, 553, 554):
            result["status"] = VerificationStatus.INVALID
            result["confidence"] = 5
            result["notes"] = f"Mailbox rejected by server: {msg}"
        elif code in (450, 451, 452):
            result["status"] = VerificationStatus.RISKY
            result["confidence"] = 40
            result["notes"] = "Server greylisted or rate-limited verification probe."
        else:
            result["status"] = VerificationStatus.UNKNOWN
            result["confidence"] = 30
            result["notes"] = f"Unexpected response from mail server: {msg}"

        return result
