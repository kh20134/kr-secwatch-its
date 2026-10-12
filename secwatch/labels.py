"""화면·보고에 쓰는 한국어 이름."""

SOURCE_LABELS = {
    "kisa": "보호나라",
    "boannews": "보안뉴스",
    "dailysecu": "데일리시큐",
    "cve": "CVE 통합",
    "ransomware": "랜섬웨어 주장",
    "kev": "CISA KEV",
    "nvd": "NVD",
    "epss": "EPSS",
}

KIND_LABELS = {
    "notice": "공지",
    "news": "뉴스",
    "cve": "취약점",
    "victim": "피해 주장",
}

BANDS = ("긴급", "높음", "주의", "참고")


def source_label(source: str) -> str:
    return SOURCE_LABELS.get(source, source)


def kind_label(kind: str) -> str:
    return KIND_LABELS.get(kind, kind)
