# pylint: skip-file
"""models for interacting with oss index api"""
#
# Copyright 2022-Present Sonatype Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from typing import Iterable, Optional, Set

# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL  # type: ignore

# pylint: disable=invalid-name


class Vulnerability:
    """
    Model class that represents a Vulnerability as received back from OSS Index.

    """

    def __init__(
        self,
        *,
        id_: str,
        display_name: str,
        title: str,
        description: str,
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        cve: Optional[str] = None,
        cwe: Optional[str] = None,
        version_ranges: Optional[Iterable[str]] = None,
        reference: str,
        external_references: Optional[Iterable[str]] = None,
    ):
        self.id = id_
        self.display_name = display_name
        self.title = title
        self.description = description
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector
        self.cve = cve
        self.cwe = cwe
        self.version_ranges = set(version_ranges or [])
        self.reference = reference
        self.external_references = set(external_references or [])

    @property
    def id(self) -> str:
        """
        OSS Index's unique UUID for this Vulnerability.

        Returns:
             `str`
        """
        return self._id

    @id.setter
    def id(self, id_: str) -> None:
        self._id = id_

    @property
    def display_name(self) -> str:
        """
        displayName returned by OSS Index

        Returns:
            `str`
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name: str) -> None:
        self._display_name = display_name

    @property
    def title(self) -> str:
        """
        title returned by OSS Index

        Returns:
            `str`
        """
        return self._title

    @title.setter
    def title(self, title: str) -> None:
        self._title = title

    @property
    def description(self) -> str:
        """
        description returned by OSS Index.

        Returns:
             `str`
        """
        return self._description

    @description.setter
    def description(self, description: str) -> None:
        self._description = description

    @property
    def cvss_score(self) -> Optional[float]:
        """
        CVSS Score returned from OSS Index.

        Returns:
             `float` if set else `None`
        """
        return self._cvss_score

    @cvss_score.setter
    def cvss_score(self, cvss_score: Optional[float]) -> None:
        self._cvss_score = cvss_score

    @property
    def cvss_vector(self) -> Optional[str]:
        """
        CVSS Vector returned from OSS Index

        Returns:
            `str` if set else `None`
        """
        return self._cvss_vector

    @cvss_vector.setter
    def cvss_vector(self, cvss_vector: Optional[str]) -> None:
        self._cvss_vector = cvss_vector

    @property
    def cwe(self) -> Optional[str]:
        """
        CWE returned from OSS Index.

        .. note:
            This is a string of the format CWE-nnn or an empty string

        Returns:
             `str` if set else `None`
        """
        return self._cwe

    @cwe.setter
    def cwe(self, cwe: Optional[str]) -> None:
        self._cwe = cwe

    @property
    def cve(self) -> Optional[str]:
        """
        CVE returned from OSS Index.

        Returns:
             `str` if set else `None`
        """
        return self._cve

    @cve.setter
    def cve(self, cve: Optional[str]) -> None:
        self._cve = cve

    @property
    def reference(self) -> str:
        """
        Reference URL to OSS Index for this Vulnerability.

        Returns:
            `str`
        """
        return self._reference

    @reference.setter
    def reference(self, reference: str) -> None:
        self._reference = reference

    @property
    def version_ranges(self) -> Set[str]:
        """
        Range of versions which are impacted by this Vulnerability.

        Returns:
            Set of `str`
        """
        return self._version_ranges

    @version_ranges.setter
    def version_ranges(self, version_ranges: Iterable[str]) -> None:
        self._version_ranges = set(version_ranges)

    @property
    def external_references(self) -> Set[str]:
        """
        List of external references that provide additional information about the vulnerability.

        Returns:
            Set of `str`
        """
        return self._external_references

    @external_references.setter
    def external_references(self, external_references: Iterable[str]) -> None:
        self._external_references = set(external_references)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Vulnerability):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash(
            (
                self.id,
                self.display_name,
                self.title,
                self.description,
                self.cvss_score,
                self.cvss_vector,
                self.cve,
                self.cwe,
                tuple(self.version_ranges),
                self.reference,
                tuple(self.external_references),
            )
        )

    def __repr__(self) -> str:
        return f"<Vulnerability id={self.id}, name={self.display_name}, cvss_score={self.cvss_score:.1f}>"


class OssIndexComponent:
    """
    Model class that represents a Component Report as received back from OSS Index.

    """

    def __init__(
        self,
        *,
        coordinates: str,
        description: Optional[str] = None,
        reference: str,
        vulnerabilities: Optional[Iterable[Vulnerability]] = None,
    ) -> None:
        self.coordinates = coordinates
        self.description = description
        self.reference = reference
        self.vulnerabilities = set(vulnerabilities or [])

    @property
    def coordinates(self) -> str:
        """
        PackageURL formatted coordinates of this Component.

        Returns:
             `str`
        """
        return self._coordinates

    @coordinates.setter
    def coordinates(self, coordinates: str) -> None:
        self._coordinates = coordinates

    @property
    def description(self) -> Optional[str]:
        """
        Description of the Component from OSS Index.

        Returns:
            `str` if set else `None`
        """
        return self._description

    @description.setter
    def description(self, description: Optional[str]) -> None:
        self._description = description

    @property
    def reference(self) -> str:
        """
        URL to this Component on OSS Index.

        Returns:
             `str`
        """
        return self._reference

    @reference.setter
    def reference(self, reference: str) -> None:
        self._reference = reference

    @property
    def vulnerabilities(self) -> Set[Vulnerability]:
        """
        Known vulnerabilities that relate to this Component.

        Returns:
             Set of `Vulnerability`
        """
        return self._vulnerabilities

    @vulnerabilities.setter
    def vulnerabilities(self, vulnerabilities: Iterable[Vulnerability]) -> None:
        self._vulnerabilities = set(vulnerabilities)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, OssIndexComponent):
            return hash(other) == hash(self)
        return False

    def __hash__(self) -> int:
        return hash(
            (
                self.coordinates,
                self.description,
                self.reference,
                tuple(self.vulnerabilities),
            )
        )

    def __repr__(self) -> str:
        return f"<OssIndexComponent coordinates={self.coordinates}>"

    def get_package_url(self) -> PackageURL:
        """
        Get a PURL representation of this components coordinates.

        Returns:
            `PackageURL`
        """
        return PackageURL.from_string(purl=self.coordinates)

    def get_max_cvss_score(self) -> float:
        """
        Get the maximum CVSS Score across all Vulnerabilities known for this Component.

        Returns:
             `float`
        """
        max_cvss_score = 0.0
        if self.vulnerabilities:
            for v in self.vulnerabilities:
                max_cvss_score = OssIndexComponent._reduce_on_max_cvss_score(
                    v=v, current_max=max_cvss_score
                )
        return max_cvss_score

    @staticmethod
    def _reduce_on_max_cvss_score(v: Vulnerability, current_max: float) -> float:
        if v.cvss_score:
            if v.cvss_score > current_max:
                return v.cvss_score
        return current_max
