from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FontTokens:
    family: str
    size_base: int
    size_small: int
    size_title: int


@dataclass(frozen=True, slots=True)
class RadiusTokens:
    sm: int
    md: int
    lg: int


@dataclass(frozen=True, slots=True)
class SpacingTokens:
    xs: int
    sm: int
    md: int
    lg: int


@dataclass(frozen=True, slots=True)
class SeverityTokens:
    low: str
    medium: str
    high: str
    critical: str


@dataclass(frozen=True, slots=True)
class VisualTokens:
    background: str
    background_alt: str
    surface: str
    surface_hover: str
    surface_selected: str
    border: str
    border_focus: str
    text: str
    text_muted: str
    text_on_primary: str
    primary: str
    primary_hover: str
    primary_disabled: str
    disabled: str
    fonts: FontTokens
    radius: RadiusTokens
    spacing: SpacingTokens
    severity: SeverityTokens


TOKENS: dict[str, VisualTokens] = {
    "dark_premium": VisualTokens(
        background="#0a1018",
        background_alt="#0f1824",
        surface="#172333",
        surface_hover="#1d2e44",
        surface_selected="#233955",
        border="#2b405a",
        border_focus="#59a6ff",
        text="#edf5ff",
        text_muted="#a9bdd5",
        text_on_primary="#f6f9ff",
        primary="#287eff",
        primary_hover="#4995ff",
        primary_disabled="#2a4568",
        disabled="#60778f",
        fonts=FontTokens(family="Inter", size_base=10, size_small=9, size_title=11),
        radius=RadiusTokens(sm=4, md=8, lg=12),
        spacing=SpacingTokens(xs=4, sm=8, md=12, lg=16),
        severity=SeverityTokens(low="#47d18c", medium="#f7ba40", high="#ff7c5c", critical="#ff4e4e"),
    ),
    "high_contrast": VisualTokens(
        background="#000000",
        background_alt="#090909",
        surface="#101010",
        surface_hover="#1a1a1a",
        surface_selected="#262626",
        border="#f0f0f0",
        border_focus="#ffea00",
        text="#ffffff",
        text_muted="#dcdcdc",
        text_on_primary="#000000",
        primary="#ffea00",
        primary_hover="#fff17b",
        primary_disabled="#5b5b5b",
        disabled="#8c8c8c",
        fonts=FontTokens(family="Segoe UI", size_base=11, size_small=10, size_title=12),
        radius=RadiusTokens(sm=2, md=4, lg=6),
        spacing=SpacingTokens(xs=4, sm=8, md=12, lg=16),
        severity=SeverityTokens(low="#72ff72", medium="#ffe866", high="#ff9f4b", critical="#ff3b3b"),
    ),
}
