from typing import Optional

from pydantic import BaseModel, Field


class DeviceSignals(BaseModel):
    """Behavioral/device telemetry captured the moment the user lands.

    This is deliberately the *only* input available to the Stage 1 fraud
    gate — no documentary evidence exists yet. A real deployment would
    populate this from client-side fingerprinting, WAF/CDN headers, and a
    device-reputation provider; here the caller supplies it directly so the
    engine's scoring logic can be exercised and tested standalone.
    """

    device_id: str = Field(..., description="Stable client/device fingerprint")
    ip_address: str = Field(..., description="Client IP address as seen by the edge")
    user_agent: str = Field(default="", description="Raw User-Agent header")
    known_device: bool = Field(
        default=False, description="True if this device has a prior trusted history"
    )
    vpn_or_datacenter_ip: bool = Field(
        default=False, description="True if IP reputation flags VPN/hosting/datacenter"
    )
    mouse_movement_entropy: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="0 = perfectly linear/scripted input, 1 = highly human-like",
    )
    time_on_page_ms: int = Field(
        default=3000,
        ge=0,
        description="Milliseconds between page load and claim submission",
    )


class ClaimRequest(BaseModel):
    """The initial claim: 'I'm a Stanford student', plus who's making it and how."""

    subject_id: Optional[str] = Field(
        default=None,
        description="Caller-supplied user/account id this claim belongs to. "
        "A new one is generated if omitted.",
    )
    claim_type: str = Field(default="student", description="What kind of claim this is")
    claim_text: str = Field(..., description="Human-readable claim, e.g. \"I'm a Stanford student\"")
    institution_name: str = Field(..., description="Institution being claimed, e.g. 'Stanford University'")
    device_signals: DeviceSignals
