"""
Email Pattern Generator:
Generates the most commonly used corporate email permutations based on
industry data (covering >95% of businesses).
"""

import re
import unicodedata
from urllib.parse import urlparse
from typing import List, Dict, Optional


def clean_domain(raw_input: str) -> str:
    """
    Cleans domain or URL input to extract the bare domain.
    E.g. 'https://www.google.com/about' -> 'google.com'
         'microsoft.com' -> 'microsoft.com'
    """
    domain = raw_input.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    # Strip port if any
    domain = domain.split(":")[0]
    # Remove leading www.
    if domain.startswith("www."):
        domain = domain[4:]
    # Strip any trailing path or slash
    domain = domain.split("/")[0].strip()
    return domain


def normalize_name(name: str) -> str:
    """
    Normalizes a name string:
    - Converts unicode to ascii (accents removed: é -> e, ñ -> n)
    - Strips punctuation, quotes, apostrophes (O'Connor -> oconnor)
    - Removes whitespace
    """
    if not name:
        return ""
    # Normalize unicode to decomposed form and filter out combining marks
    normalized = unicodedata.normalize('NFKD', name)
    ascii_bytes = normalized.encode('ASCII', 'ignore')
    ascii_str = ascii_bytes.decode('utf-8').lower()
    # Remove all non-alphanumeric characters
    cleaned = re.sub(r'[^a-z0-9]', '', ascii_str)
    return cleaned


class EmailPatternGenerator:
    """
    Generates ranked candidate email addresses from a person's name and company domain.
    """

    # Industry pattern distribution weights
    PATTERNS_WITH_LAST_NAME = [
        ("{first}.{last}", "First . Last", 48, "Most popular modern standard (Google Workspace/Tech)"),
        ("{f}{last}", "First Initial + Last", 24, "Corporate/Enterprise legacy standard (Exchange)"),
        ("{first}", "First Name only", 12, "Startups / Small companies (<50 employees)"),
        ("{first}{last}", "First + Last", 6, "Mid-size companies / Traditional"),
        ("{first}_{last}", "First _ Last", 4, "Common alternative format"),
        ("{f}.{last}", "First Initial . Last", 2, "Common corporate variation"),
        ("{first}{l}", "First + Last Initial", 2, "Common when first names collide"),
        ("{last}.{first}", "Last . First", 1, "Popular in Europe & Asia"),
        ("{first}-{last}", "First - Last", 1, "Modern alternative"),
        ("{last}{f}", "Last + First Initial", 1, "Common in academic/enterprise"),
        ("{last}", "Last Name only", 1, "Rare / Executive"),
    ]

    PATTERNS_FIRST_ONLY = [
        ("{first}", "First Name only", 70, "Single name domain standard"),
        ("{first}1", "First + 1", 15, "Numbered fallback"),
        ("contact", "Generic Role", 15, "Fallback role"),
    ]

    @classmethod
    def generate(cls, first_name: str, last_name: Optional[str], domain: str) -> List[Dict]:
        """
        Generates candidate emails with their metadata.
        Returns a list of dicts:
        [
            {
                "email": "satya.nadella@microsoft.com",
                "pattern": "{first}.{last}",
                "label": "First . Last",
                "probability": "48%",
                "description": "Most popular modern standard"
            },
            ...
        ]
        """
        domain = clean_domain(domain)
        first = normalize_name(first_name)
        last = normalize_name(last_name or "")

        if not first:
            raise ValueError("First name is required to generate email candidates.")
        if not domain:
            raise ValueError("Domain is required to generate email candidates.")

        candidates = []
        seen_emails = set()

        if last:
            f = first[0]
            l = last[0]
            context = {
                "first": first,
                "last": last,
                "f": f,
                "l": l
            }
            pattern_list = cls.PATTERNS_WITH_LAST_NAME
        else:
            context = {"first": first}
            pattern_list = cls.PATTERNS_FIRST_ONLY

        for pattern_str, label, prob, desc in pattern_list:
            local_part = pattern_str.format(**context)
            email = f"{local_part}@{domain}"
            if email not in seen_emails:
                seen_emails.add(email)
                candidates.append({
                    "email": email,
                    "local_part": local_part,
                    "domain": domain,
                    "pattern": pattern_str,
                    "label": label,
                    "probability": f"{prob}%",
                    "weight": prob,
                    "description": desc
                })

        return candidates
