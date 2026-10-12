from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    "architecture.png": 20_000,
    "dashboard.png": 30_000,
    "report.png": 30_000,
    "dashboard-mobile.png": 20_000,
}


def test_doc_images_are_png():
    for name, minimum in IMAGES.items():
        path = ROOT / "docs" / "images" / name
        data = path.read_bytes()
        assert data.startswith(b"\x89PNG\r\n\x1a\n"), name
        assert len(data) > minimum, name
