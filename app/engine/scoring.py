"""Small shared scoring utilities used by both fraud-engine passes."""


def clamp(value: float, lo: int = 0, hi: int = 100) -> int:
    return int(max(lo, min(hi, round(value))))


def weighted_sum(components: dict, weights: dict) -> int:
    """components/weights are {name: value} dicts sharing the same keys.
    Values are expected already on a 0-100 scale; weights should sum to ~1.0."""
    total = sum(components[k] * weights[k] for k in weights)
    return clamp(total)
