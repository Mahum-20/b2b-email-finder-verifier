# B2B Email Pattern Finder & Verification Engine

A Python tool that discovers and verifies corporate email addresses using the same 5-stage pipeline and pattern-prediction algorithms used by platforms like **Hunter.io** and **Apollo.io**.

---

## 📌 How It Works

### Phase 1: Pattern Generation
When given a **Person's Name** (e.g. *Satya Nadella*) and a **Domain** (e.g. *microsoft.com*), the system generates prioritized candidate addresses based on real-world B2B email distribution:
1. `{first}.{last}@domain.com` (~48%)
2. `{f}{last}@domain.com` (~24%)
3. `{first}@domain.com` (~12%)
4. `{first}{last}@domain.com` (~6%)
5. `{first}_{last}@domain.com` (~4%)
6. `{f}.{last}@domain.com` (~2%)
7. `{first}{l}@domain.com` (~2%)
8. `{last}.{first}@domain.com` (~1%)
9. `{first}-{last}@domain.com` (~1%)
10. `{last}{f}@domain.com` (~1%)
11. `{last}@domain.com` (~1%)

### Phase 2: The 5-Stage Verification Pipeline
For each candidate email, the engine runs:
1. **RFC 5322 Syntax Check:** Length limits, `@` count, invalid character check.
2. **DNS & MX Records Lookup:** Queries live DNS for mail exchangers ordered by priority, with fallback to RFC 5321 'A' records.
3. **Disposable & Role Account Detection:** Filters out burner mailboxes (`mailinator.com`, etc.) and generic role inboxes (`info@`, `sales@`, `support@`).
4. **Catch-All (Accept-All) Detection:** Probes the mail server with a randomized UUID mailbox. If the server says `250 OK` to a non-existent user, it flags the domain as Catch-All.
5. **SMTP Handshake Simulation (`RCPT TO`):**
   - `HELO mailverifier.local`
   - `MAIL FROM: <verify@check.com>`
   - `RCPT TO: <candidate@domain.com>`
   - Reads server response: `250 OK` (User exists) or `550 User Unknown` (Rejected).
   - Sends `QUIT` without transmitting `DATA` (no email is ever delivered).

---

## 🚀 Getting Started

### 1. Requirements
Ensure you have Python 3.8+ installed with `dnspython`, `pandas`, and `streamlit`:
```bash
pip install dnspython pandas streamlit
```

### 2. Running via Command Line (CLI)
You can run it with arguments:
```bash
python main.py --first "Patrick" --last "Collison" --domain "stripe.com"
```
Or run it interactively:
```bash
python main.py
```

### 3. Running via Web Dashboard (Streamlit)
Launch the interactive web UI:
```bash
streamlit run app.py
```
Open `http://localhost:8501` in your browser. You can enter names, adjust timeouts, view real-time MX records, and download candidate tables as CSV.

---

## 🌐 Note on Outbound Port 25
* **Home ISPs & Residential Wi-Fi:** Almost all residential ISPs block outbound TCP port 25 to protect against malware sending spam.
* **How Apollo and Hunter handle this:** Commercial verification platforms host their verification workers on dedicated cloud servers (e.g., OVH, Linode, AWS EC2 with port 25 unblocked upon request) configured with reverse DNS (PTR) records.
* **Fallback:** When port 25 is blocked locally, this tool verifies DNS & MX records and ranks candidate emails by industry statistical probability.
