"""
B2B Email Pattern Finder & Verifier CLI
Combines pattern generation with RFC 5322, DNS MX, Catch-All, and SMTP verification.
"""

import sys
import argparse
from pattern_generator import EmailPatternGenerator, clean_domain
from verifier import EmailVerifier, VerificationStatus


def format_table(rows, headers):
    """Simple ASCII table formatter."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Format header
    header_str = " | ".join(f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers)))
    separator = "-+-".join("-" * col_widths[i] for i in range(len(headers)))

    out = [header_str, separator]
    for row in rows:
        out.append(" | ".join(f"{str(row[i]):<{col_widths[i]}}" for i in range(len(headers))))
    return "\n".join(out)


def run_finder_and_verifier(first_name: str, last_name: str, domain_input: str):
    domain = clean_domain(domain_input)
    print("\n" + "=" * 65)
    print("        B2B EMAIL PATTERN FINDER & SMTP VERIFIER")
    print("=" * 65)
    print(f"Target Person : {first_name} {last_name}".strip())
    print(f"Target Domain : {domain}")
    print("-" * 65)

    # 1. Generate Candidates
    try:
        candidates = EmailPatternGenerator.generate(first_name, last_name, domain)
    except Exception as e:
        print(f"[ERROR] Failed to generate email patterns: {e}")
        return

    print(f"[*] Generated {len(candidates)} most probable email patterns:")
    for idx, c in enumerate(candidates, 1):
        print(f"    {idx:2d}. {c['email']:<35} ({c['label']} ~ {c['probability']})")
    print("-" * 65)

    # 2. Initialize Verifier and Check Domain
    verifier = EmailVerifier(smtp_timeout=5.0)

    print("[*] STEP 1 & 2: Checking DNS & MX Records...")
    mx_records, mx_msg = verifier.get_mx_records(domain)
    if not mx_records:
        print(f"[-] [FAIL] {mx_msg}")
        print("[-] Domain cannot receive email. Aborting verification.")
        return

    print(f"[+] [PASS] Found {len(mx_records)} MX servers:")
    for mx in mx_records[:3]:
        print(f"    - {mx}")

    primary_mx = mx_records[0]

    # Check Port 25
    print("\n[*] Checking Outbound Port 25 Connectivity...")
    port_blocked = verifier.is_port_25_blocked(primary_mx)
    if port_blocked:
        print("    [!] NOTE: Outbound Port 25 is blocked or filtered by your local ISP/Network.")
        print("    [!] (Consumer ISPs and residential Wi-Fi block port 25 to prevent spam.)")
        print("    [!] Cloud tools like Apollo & Hunter run on dedicated servers with unblocked port 25.")
        print("    [!] The tool will verify DNS/MX and score candidates by pattern probability.")
    else:
        print("    [+] Port 25 is OPEN! Real-time SMTP Handshake is active.")

    # Check Catch-All
    print("\n[*] STEP 4: Checking Catch-All (Accept-All) Status...")
    is_catch_all, ca_msg = verifier.check_catch_all(domain, primary_mx)
    if is_catch_all is True:
        print("    [!] Server is CATCH-ALL: It accepts all addresses regardless of whether the user exists.")
    elif is_catch_all is False:
        print("    [+] Server is NOT Catch-All: Bad emails are actively rejected by the mail server.")
    else:
        print(f"    [~] {ca_msg}")

    # 3. Verify Candidate Patterns
    print("\n[*] STEP 5: Verifying Candidate Patterns...")
    table_rows = []
    found_valid = None

    for idx, c in enumerate(candidates):
        email = c["email"]
        sys.stdout.write(f"    Testing {email:<35} ... ")
        sys.stdout.flush()

        res = verifier.verify(email, pattern_weight=c["weight"])
        status = res["status"]
        confidence_val = res['confidence']
        confidence = f"{confidence_val}%"

        sys.stdout.write(f"[{status} - {confidence}]\n")
        sys.stdout.flush()

        rec = "⭐ TOP PREDICTION" if idx == 0 else ""
        if status == VerificationStatus.VALID:
            rec = "✅ VERIFIED ACTIVE"

        table_rows.append([
            email,
            c["label"],
            c["probability"],
            status,
            confidence,
            rec
        ])

        if status == VerificationStatus.VALID and not found_valid:
            found_valid = email

    print("\n" + "=" * 80)
    print("                              VERIFICATION SUMMARY")
    print("=" * 80)

    headers = ["Email Candidate", "Pattern Format", "Share", "Status", "Confidence", "Recommendation"]
    print(format_table(table_rows, headers))
    print("=" * 80)

    # Clearly declare which email is accurate
    best_candidate = found_valid if found_valid else candidates[0]["email"]
    best_pattern = candidates[0]["label"]
    best_prob = candidates[0]["probability"]

    print("\n" + "★" * 80)
    if found_valid:
        print(f"  [RESULT] 🎯 VERIFIED WORKING EMAIL: {found_valid}")
        print("  Status : Live SMTP server confirmed mailbox exists (250 OK).")
    else:
        print(f"  [RESULT] 🎯 MOST ACCURATE PREDICTED EMAIL: {best_candidate}")
        print(f"  Format : {best_pattern} (~{best_prob} of businesses at this domain)")
        if port_blocked:
            print("  Reason : Outbound Port 25 is filtered by your local ISP, preventing live mailbox ping.")
            print(f"           DNS and MX mail servers are 100% verified for '{domain}'.")
            print(f"           '{best_candidate}' is statistically the #1 most accurate address.")
        elif is_catch_all:
            print("  Reason : Mail server is Catch-All (accepts all incoming emails).")
    print("★" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Find and verify business email addresses using pattern recognition and SMTP handshake.")
    parser.add_argument("--first", help="Person's first name (e.g. Satya)")
    parser.add_argument("--last", help="Person's last name (e.g. Nadella)")
    parser.add_argument("--domain", help="Company domain or website (e.g. microsoft.com or https://stripe.com)")

    args = parser.parse_args()

    first_name = args.first
    last_name = args.last
    domain = args.domain

    if not first_name or not domain:
        print("\n--- Enter Target Details ---")
        first_name = input("Enter First Name: ").strip()
        last_name = input("Enter Last Name (optional): ").strip()
        domain = input("Enter Company Domain or Website (e.g. stripe.com): ").strip()

    if not first_name or not domain:
        print("[ERROR] First name and domain are required.")
        sys.exit(1)

    run_finder_and_verifier(first_name, last_name, domain)


if __name__ == "__main__":
    main()
