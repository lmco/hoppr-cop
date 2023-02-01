# pylint: skip-file
##
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
import re
from json import JSONEncoder
from typing import Any, Dict

# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL  # type: ignore

from .model import OssIndexComponent, Vulnerability


def pythonify_key_names(d: Dict[str, Any]) -> Dict[Any, Any]:
    named_d: Dict[Any, Any] = {}
    # Covert Key Names
    for k, v in d.items():
        new_k = re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower()

        if k == "id":
            # Special case for reserved keyword
            new_k = "id_"

        named_d[new_k] = v
    return named_d


def json_decoder(o: object) -> object:
    if isinstance(o, dict):
        named_o = pythonify_key_names(d=o)
        try:
            if "coordinates" in named_o.keys():
                return OssIndexComponent(**named_o)
            elif "id_" in named_o.keys():
                return Vulnerability(**named_o)
        except TypeError as e:
            print(f"Error was on {o}")
            raise e

    raise ValueError(f"Unknown value in JSON being decoded: {o}")


_HYPHENATED_ATTRIBUTES = ["bom_ref", "mime_type", "x_trust_boundary"]
_PYTHON_TO_JSON_NAME = re.compile(r"_([a-z])")


class OssIndexJsonEncoder(JSONEncoder):
    def default(self, o: Any) -> Any:
        # Sets
        if isinstance(o, set):
            return list(o)

        # Classes
        if isinstance(o, object):
            d: Dict[Any, Any] = {}
            for k, v in o.__dict__.items():
                # Remove leading _ in key names
                new_key = k[1:]
                if new_key.startswith("_") or "__" in new_key:
                    continue

                # Convert pythonic names to JSON names
                # e.g. 'external_references' to 'externalReferences'
                #
                # Some special cases are hyphenated, not camel case
                if new_key in _HYPHENATED_ATTRIBUTES:
                    new_key = new_key.replace("_", "-")
                elif "_" in new_key:
                    new_key = _PYTHON_TO_JSON_NAME.sub(
                        lambda x: x.group(1).upper(), new_key
                    )

                if v or v is False:
                    if isinstance(v, PackageURL):
                        # Special handling of PackageURL instances which JSON would otherwise automatically encode to
                        # an Array
                        v = str(v.to_string())
                    d[new_key] = v

            return d

        # Fallback to default
        super().default(o=o)
