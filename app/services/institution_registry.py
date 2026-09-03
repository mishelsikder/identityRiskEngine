"""Mock institution registry.

Stands in for a real system-of-record lookup (IPEDS, Clearinghouse, a
partnered SSO/eduroam federation, etc.). Institution names are matched
case/whitespace-insensitively; each entry carries the email domain(s) that
count as valid proof of affiliation.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Institution:
    name: str
    domains: tuple


_REGISTRY = {
    "stanford university": Institution("Stanford University", ("stanford.edu",)),
    "massachusetts institute of technology": Institution(
        "Massachusetts Institute of Technology", ("mit.edu",)
    ),
    "mit": Institution("Massachusetts Institute of Technology", ("mit.edu",)),
    "harvard university": Institution("Harvard University", ("harvard.edu",)),
    "university of california, berkeley": Institution(
        "University of California, Berkeley", ("berkeley.edu",)
    ),
    "uc berkeley": Institution("University of California, Berkeley", ("berkeley.edu",)),
    "carnegie mellon university": Institution(
        "Carnegie Mellon University", ("cmu.edu", "andrew.cmu.edu")
    ),
    "university of washington": Institution("University of Washington", ("uw.edu",)),
}


def _normalize(name: str) -> str:
    return " ".join(name.strip().lower().split())


def lookup(institution_name: str) -> Optional[Institution]:
    return _REGISTRY.get(_normalize(institution_name))


def email_domain_matches(institution_name: str, email: str) -> bool:
    """True if the email's domain belongs to the claimed institution.

    Falls back to a generic '.edu' check when the institution isn't in the
    mock registry, so the demo doesn't hard-fail on schools we simply
    haven't seeded — a real system would instead treat 'unknown
    institution' as its own risk signal (see evidence_checker).
    """
    domain = email.split("@")[-1].lower()
    institution = lookup(institution_name)
    if institution is not None:
        return any(domain == d or domain.endswith(f".{d}") for d in institution.domains)
    return domain.endswith(".edu")
