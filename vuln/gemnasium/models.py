"""Models fo Gitlab Gemnasium Vulnerabilities """
from typing import List, Optional

from pydantic import BaseModel


class GemnasiumVulnerability(BaseModel):
    """Models fo Gitlab Gemnasium Vulnerabilities"""

    identifiers: List[str]
    title: str
    description: str
    pubdate: str
    solution: Optional[str] = ""
    affected_range: str
    affected_versions: str
    not_impacted: Optional[str] = None
    urls: List[str] = []
    cwe_ids: Optional[List[str]]
    cvss_v2: Optional[str] = None
    cvss_v3: Optional[str] = None
