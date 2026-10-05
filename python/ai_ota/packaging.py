"""Read access to `.otapkg` v1 files.

Implements the Python side of ADR 0001 / issue #2: the native module (`ai_ota._native`,
a PyO3 wrapper around the `ota-package` Rust crate) never exposes raw CBOR — it returns a
JSON string, which this module turns into a plain Python dict. ML engineers only ever see
that dict; only embedded engineers need to look at the CBOR/byte-level spec in
`docs/reference/formats/`.
"""

from __future__ import annotations

import json
from typing import Any

from ai_ota import _native


def inspect(path: str) -> dict[str, Any]:
    """Parses a `.otapkg` v1 file and returns its header/manifest/chunk-index/signature
    as a plain Python dict.

    Raises:
        ValueError: if the file is not a valid `.otapkg` v1 package.
    """
    return json.loads(_native.parse_package_json(path))
