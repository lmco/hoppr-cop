"""Models fo Gitlab Gemnasium Vulnerabilities """
# This file is part of hoppr-cop
#
# Licensed under the MIT License;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://opensource.org/licenses/MIT
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Copyright (c) 2022 Lockheed Martin Corporation
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
