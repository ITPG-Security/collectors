# SENTINEL ONE MITIGATION STATUS ENUM
MITIGATED = "mitigated"
MARKED_AS_BENIGN = "marked_as_benign"
NOT_MITIGATED = "not_mitigated"


def is_prevented(mitigationStatus: str) -> bool:
    return mitigationStatus == MITIGATED