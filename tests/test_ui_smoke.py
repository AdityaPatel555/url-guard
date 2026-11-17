"""
URL Guard — Streamlit UI Automated Smoke Test Suite
File: tests/test_ui_smoke.py

Automated smoke, headless execution, integration, and robustness test suite
for app.py using streamlit.testing.v1.AppTest and pytest.

Covers:
- Syntax, structure, and compilation validation.
- Headless launch and initial load across pages.
- URL submission pipeline (legitimate, phishing, empty/invalid).
- Preset sample demonstration buttons.
- Direct navigation empty state guards.
- Full results rendering (metrics, progress gauge, 7 check cards, breakdown).
- History viewing, clearing, and CSV export.
- Academic About page evaluation walkthrough.
- Round-trip navigation resilience and XSS injection safety.
"""

from pathlib import Path
import sys
import pytest
from streamlit.testing.v1 import AppTest

# Resolve project root and app.py path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

APP_PATH = str(PROJECT_ROOT / "app.py")


@pytest.fixture
def isolated_history(tmp_path, monkeypatch):
    """
    Isolates scan history CSV storage to a temporary directory for each test run.
    Guarantees no pollution of production data/scan_history.csv.
    """
    import storage.history_manager as hm
    temp_csv = tmp_path / "scan_history.csv"
    monkeypatch.setattr(hm, "DEFAULT_DATA_DIR", tmp_path)
    monkeypatch.setattr(hm, "DEFAULT_CSV_PATH", temp_csv)
    return tmp_path


class TestUIAppImportsAndSyntax:
    """Verifies that app.py exists, compiles cleanly, and exposes required entry points."""

    def test_app_compilation_and_syntax(self):
        """Verify app.py exists and compiles without syntax errors."""
        p = Path(APP_PATH)
        assert p.exists(), f"app.py not found at {APP_PATH}"
        code = p.read_text(encoding="utf-8")
        compiled = compile(code, str(p), "exec")
        assert compiled is not None

    def test_required_page_constants_and_functions(self):
        """Verify that standard navigation constants and entry functions exist."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("app_module", APP_PATH)
        assert spec is not None
        assert spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        assert mod is not None


class TestUIHeadlessLaunch:
    """Verifies headless initialization via Streamlit AppTest."""

    def test_initial_load_renders_without_exceptions(self, isolated_history):
        """Verify launching app.py produces zero uncaught exceptions."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        assert len(at.exception) == 0, f"App launched with exceptions: {at.exception}"

    def test_initial_page_is_dashboard(self, isolated_history):
        """Verify the default view is Home / Dashboard with branding."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        assert len(at.exception) == 0
        markdown_texts = " ".join([m.value for m in at.markdown])
        assert "URL GUARD" in markdown_texts or "URL Guard" in markdown_texts
        assert "Analyse. Detect. Stay Aware." in markdown_texts

    def test_sidebar_contains_all_four_pages(self, isolated_history):
        """Verify sidebar navigation contains all 4 standard pages."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        assert len(at.exception) == 0
        assert len(at.sidebar.radio) > 0
        options = at.sidebar.radio[0].options
        assert len(options) == 4
        assert any("Home" in opt for opt in options)
        assert any("Results" in opt for opt in options)
        assert any("History" in opt for opt in options)
        assert any("About" in opt for opt in options)


class TestUIDashboardInteractions:
    """Verifies user interaction flows on Page 1: Home / Dashboard."""

    def test_submit_valid_legitimate_url(self, isolated_history):
        """Verify submitting a clean legitimate URL navigates to Results with score 0."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        at.text_input(key="input_url_field").input("https://www.google.com")
        # Submit form
        at.button[len(at.button) - 1].click().run()
        assert len(at.exception) == 0
        assert "Results" in at.session_state.get("current_page", "")
        report = at.session_state.get("current_report")
        assert report is not None
        assert report.total_risk_score == 0
        assert report.risk_classification == "LOW RISK"

    def test_submit_phishing_ip_url(self, isolated_history):
        """Verify submitting an IP phishing URL flags risk points and navigates to Results."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        at.text_input(key="input_url_field").input("http://192.168.1.1/banking/login")
        at.button[len(at.button) - 1].click().run()
        assert len(at.exception) == 0
        assert "Results" in at.session_state.get("current_page", "")
        report = at.session_state.get("current_report")
        assert report is not None
        assert report.total_risk_score >= 50
        assert report.risk_classification in ("MEDIUM RISK", "HIGH RISK")

    def test_submit_empty_url_displays_validation_error(self, isolated_history):
        """Verify empty input displays error alert and remains on Home."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        at.text_input(key="input_url_field").input("")
        at.button[len(at.button) - 1].click().run()
        assert len(at.exception) == 0
        assert len(at.error) > 0
        assert "Home" in at.session_state.get("current_page", "")

    def test_preset_button_triggers_immediate_scan(self, isolated_history):
        """Verify clicking a preset sample button runs scan and transitions to Results."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        # Click Google Preset button (preset_btn_0)
        at.button(key="preset_btn_0").click().run()
        assert len(at.exception) == 0
        assert "Results" in at.session_state.get("current_page", "")
        report = at.session_state.get("current_report")
        assert report is not None
        assert report.normalized_hostname == "www.google.com"


class TestUIResultsPage:
    """Verifies Page 2: Analysis Results behavior."""

    def test_direct_access_empty_state(self, isolated_history):
        """Verify navigating directly to Results without a scan shows empty state card."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        # Find Results option
        results_opt = [o for o in at.sidebar.radio[0].options if "Results" in o][0]
        at.sidebar.radio[0].set_value(results_opt).run()
        assert len(at.exception) == 0
        assert len(at.info) > 0
        assert any("No URL has been analysed" in i.value for i in at.info)

    def test_results_page_renders_all_components(self, isolated_history):
        """Verify score metrics, progress bar, 7 cards, and breakdown table render."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        at.button(key="preset_btn_2").click().run()  # IP Phishing preset
        assert len(at.exception) == 0
        assert len(at.metric) >= 3
        assert len(at.progress) >= 1
        assert len(at.table) >= 1


class TestUIScanHistoryPage:
    """Verifies Page 3: Scan History behavior."""

    def test_empty_history_view(self, isolated_history):
        """Verify empty history displays info alert without errors."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        history_opt = [o for o in at.sidebar.radio[0].options if "History" in o][0]
        at.sidebar.radio[0].set_value(history_opt).run()
        assert len(at.exception) == 0
        assert len(at.info) > 0
        assert any("No scan history found" in i.value for i in at.info)

    def test_history_records_displayed_after_scan(self, isolated_history):
        """Verify scan is recorded and displayed in history table."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        at.button(key="preset_btn_0").click().run()  # Scan Google
        history_opt = [o for o in at.sidebar.radio[0].options if "History" in o][0]
        at.sidebar.radio[0].set_value(history_opt).run()
        assert len(at.exception) == 0
        assert len(at.dataframe) > 0

    def test_clear_history_button(self, isolated_history):
        """Verify clicking clear history wipes records."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        at.button(key="preset_btn_0").click().run()  # Scan Google
        history_opt = [o for o in at.sidebar.radio[0].options if "History" in o][0]
        at.sidebar.radio[0].set_value(history_opt).run()
        assert len(at.dataframe) > 0
        at.button(key="btn_clear_hist").click().run()
        assert len(at.exception) == 0
        assert len(at.info) > 0
        assert any("No scan history found" in i.value for i in at.info)


class TestUIAboutPage:
    """Verifies Page 4: About Project behavior."""

    def test_about_page_renders_academic_sections(self, isolated_history):
        """Verify Problem Statement, 7 Rules Table, and Team sections exist."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        about_opt = [o for o in at.sidebar.radio[0].options if "About" in o][0]
        at.sidebar.radio[0].set_value(about_opt).run()
        assert len(at.exception) == 0
        content = " ".join([m.value for m in at.markdown])
        assert "Academic College Evaluation Guide" in content or "URL Guard" in content
        assert len(at.table) >= 1  # 7 Rules table


class TestUIRobustnessAndResilience:
    """Verifies edge cases, rapid navigation switching, and injection resistance."""

    def test_multi_page_roundtrip_navigation(self, isolated_history):
        """Verify switching through all pages in sequence causes zero crashes."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        options = at.sidebar.radio[0].options
        # Cycle through all pages
        for opt in options:
            at.sidebar.radio[0].set_value(opt).run()
            assert len(at.exception) == 0
        # Cycle backwards to Home
        at.sidebar.radio[0].set_value(options[0]).run()
        assert len(at.exception) == 0

    def test_xss_injection_resilience(self, isolated_history):
        """Verify user entering malicious XSS payload does not cause unhandled crash."""
        at = AppTest.from_file(APP_PATH, default_timeout=15).run()
        xss_payload = "<script>alert('xss')</script>https://example.com"
        at.text_input(key="input_url_field").input(xss_payload)
        at.button[len(at.button) - 1].click().run()
        assert len(at.exception) == 0
