"""
Aegis SecurityEvent — Pydantic Schema Validation (Stage 1)
===========================================================
Validates incoming log records before they enter the classifier pipeline.
Invalid records are dropped immediately with error counters.

This is the first gate in the 3-stage pipeline:
  Stage 1: Pydantic Validation → Stage 2: Static Filtering → Stage 3: Thresholding
"""

from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class SecurityEvent(BaseModel):
    """
    Normalized security event from the L0 log pipeline.
    
    Required fields: timestamp, message
    All other fields have sensible defaults so partially-parsed logs
    still pass validation (with reduced information quality).
    """

    # === Required Fields ===
    timestamp: str = Field(..., description="ISO8601 timestamp, e.g. 2026-07-06T10:30:00Z")
    message: str = Field(..., min_length=1, description="Log message body")

    # === Source Identification ===
    facility: str = Field(default="", description="Log source: apigw, waf, app, edr, iam...")
    severity: str = Field(default="info", description="Log severity level")
    sourceIp: str = Field(default="", description="Source IP address")
    statusCode: int = Field(default=0, ge=0, le=999, description="HTTP status code")

    # === Content Fields ===
    decodedPayload: str = Field(default="", description="URL-decoded / base64-decoded payload")
    agent: str = Field(default="", description="HTTP User-Agent header")
    method: str = Field(default="GET", description="HTTP method")

    # === Enrichment Fields (from parser) ===
    threatFlagged: bool = Field(default=False, description="Pre-flagged by regex rules")
    threatType: Optional[str] = Field(default=None, description="Threat type if flagged")
    assetCritical: str = Field(default="LOW", description="Asset criticality: LOW/MEDIUM/HIGH/CRITICAL")
    geoIp: Optional[str] = Field(default=None, description="GeoIP country/city")
    asn: Optional[str] = Field(default=None, description="ASN organization")

    # === ECS Fields ===
    ecs_version: Optional[str] = Field(default=None, alias="ecs.version")
    event_category: Optional[Any] = Field(default=None, alias="event.category")
    event_kind: Optional[str] = Field(default=None, alias="event.kind")
    service_name: Optional[str] = Field(default=None, alias="service.name")
    url_original: Optional[str] = Field(default=None, alias="url.original")

    model_config = {"populate_by_name": True, "extra": "allow"}

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v):
        if isinstance(v, str):
            return v.lower().strip()
        return "info"

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, v):
        if isinstance(v, str):
            return v.upper().strip()
        return "GET"

    @field_validator("sourceIp", mode="before")
    @classmethod
    def normalize_ip(cls, v):
        if v is None:
            return ""
        return str(v).strip()


class SecurityEventValidator:
    """
    Validates raw log dicts against the SecurityEvent schema.
    Tracks validation stats for monitoring.
    """

    def __init__(self):
        self.stats = {
            "total_validated": 0,
            "valid": 0,
            "invalid_dropped": 0,
            "missing_timestamp": 0,
            "missing_message": 0,
            "other_errors": 0,
        }

    def validate(self, record: dict) -> Optional[dict]:
        """
        Validate a raw log record.

        Returns:
            dict: The validated (and potentially cleaned) record, or None if invalid.
        """
        self.stats["total_validated"] += 1

        try:
            event = SecurityEvent(**record)
            self.stats["valid"] += 1
            # Return as dict with original extra fields preserved
            validated = event.model_dump(by_alias=False, exclude_none=True)
            # Merge back any extra fields not in the model
            for key, val in record.items():
                if key not in validated:
                    validated[key] = val
            return validated

        except Exception as e:
            self.stats["invalid_dropped"] += 1
            error_str = str(e).lower()
            if "timestamp" in error_str:
                self.stats["missing_timestamp"] += 1
            elif "message" in error_str:
                self.stats["missing_message"] += 1
            else:
                self.stats["other_errors"] += 1
            return None

    def get_stats(self):
        return self.stats.copy()
