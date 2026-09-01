import os

from streamlit.testing.v1 import AppTest


def test_app_initial_render():
    """Verifies that Streamlit app initializes, sets title, loads presets and controls without exceptions."""
    app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
    at = AppTest.from_file(app_path, default_timeout=10)
    at.run()

    # Verify no unhandled exceptions in the script run
    assert not at.exception

    # Verify sidebar and main components are present
    assert len(at.sidebar) > 0
    assert len(at.text_area) >= 1
    assert len(at.button) >= 1

    # Verify scenario selector has default preset loaded
    assert "Flask" in at.text_area[0].value or "SQL" in at.text_area[0].value


def test_load_css_function():
    from app import load_css

    css_content = load_css()
    assert "<style>" in css_content
    assert "</style>" in css_content
    assert "Inter" in css_content or "stApp" in css_content
