# server/custom_hidden_text_watermark.py

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import Optional, Any, Dict
import hashlib

from watermarking_method import WatermarkingMethod

try:
    # prefer modern name if you have it
    from pypdf import PdfReader, PdfWriter  # type: ignore
except Exception:
    # fall back to PyPDF2 if that is what the project uses
    from PyPDF2 import PdfReader, PdfWriter  # type: ignore


META_KEY = "/WatermarkSecret"


@dataclass
class HiddenTextWatermark(WatermarkingMethod):
    """
    Watermarking method that hides the secret in the PDF metadata.

    The secret is stored as:
        "<secret>|<sha256(key || secret)>"
    under the metadata key /WatermarkSecret.

    This is invisible in normal viewing but easy for you to read back
    via the API.
    """

    name: str = "hidden_text"
    description: str = "Embed the secret in PDF metadata as hidden text"

    # helper: build payload to store
    def _encode_payload(self, secret: str, key: str) -> str:
        sec_bytes = secret.encode("utf-8")
        key_bytes = key.encode("utf-8")
        mac = hashlib.sha256(key_bytes + sec_bytes).hexdigest()
        return f"{secret}|{mac}"

    # helper: verify and recover secret from stored payload
    def _decode_payload(self, payload: str, key: str) -> Optional[str]:
        try:
            secret, mac = payload.split("|", 1)
        except ValueError:
            return None

        sec_bytes = secret.encode("utf-8")
        key_bytes = key.encode("utf-8")
        expected = hashlib.sha256(key_bytes + sec_bytes).hexdigest()
        if mac != expected:
            return None
        return secret

    def is_applicable(self, pdf: Any, position: Optional[str] = None) -> bool:
        """
        Simple applicability check.

        This method only needs the PDF to be a well formed file that
        pypdf / PyPDF2 can open. We do not care about position here.
        """
        try:
            if isinstance(pdf, (bytes, bytearray)):
                PdfReader(BytesIO(pdf))
            else:
                # assume path like watermarking_utils does
                PdfReader(str(pdf))
            return True
        except Exception:
            return False

    def add_watermark(
        self,
        pdf: Any,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """
        pdf: path (str / PathLike) or raw bytes, depending on how
             watermarking_utils calls us.
        secret: the secret you want to embed
        key: per document or global key
        position: ignored for this method
        """
        # load source
        if isinstance(pdf, (bytes, bytearray)):
            reader = PdfReader(BytesIO(pdf))
        else:
            reader = PdfReader(str(pdf))

        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        # copy existing metadata and add our hidden field
        meta: Dict[str, Any] = dict(reader.metadata or {})
        payload = self._encode_payload(secret, key)
        meta[META_KEY] = payload
        writer.add_metadata(meta)

        out = BytesIO()
        writer.write(out)
        return out.getvalue()

    def read_secret(
        self,
        pdf: bytes,
        key: str,
        position: Optional[str] = None,
    ) -> Optional[str]:
        """
        Given a watermarked PDF (bytes) and the key, recover the secret.

        Returns the secret string, or None if not present / invalid.
        """
        reader = PdfReader(BytesIO(pdf))
        info = reader.metadata or {}
        payload = info.get(META_KEY)
        if not payload:
            return None
        return self._decode_payload(str(payload), key)

    def get_usage(self) -> str:
        return (
            "Hidden text watermark in PDF metadata. "
            "Use method='hidden_text'. The 'key' is a string known to you, "
            "and 'secret' is what identifies the recipient or session."
        )
