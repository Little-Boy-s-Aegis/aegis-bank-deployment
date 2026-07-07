"""
Frontend Security Static Analysis Tests
========================================

Scans the frontend source code for common security vulnerabilities without
requiring a running server. Uses os.walk + regex to inspect .tsx/.ts/.js files
in both ``FE_Web/src`` and ``dashboard/frontend/src``.

Covers:
  - XSS prevention (dangerouslySetInnerHTML, innerHTML, eval, document.write, …)
  - Authentication security (token storage, hardcoded credentials, …)
  - CSP & security-header configuration
  - Sensitive data exposure (console.log, source maps, debug flags, …)

Run with::

    pytest tests/test_frontend_security.py -v
"""

import os
import re
import glob
from pathlib import Path
from typing import List, Tuple

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
if BASE_DIR.name == "aegis-bank-deployment":
    PROJECT_ROOT = BASE_DIR.parent
else:
    PROJECT_ROOT = BASE_DIR

FE_WEB_SRC = PROJECT_ROOT / "FE_Web" / "src"
DASHBOARD_SRC = PROJECT_ROOT / "dashboard" / "frontend" / "src"
NEXT_CONFIG_CANDIDATES = [
    PROJECT_ROOT / "FE_Web" / "next.config.ts",
    PROJECT_ROOT / "FE_Web" / "next.config.js",
    PROJECT_ROOT / "FE_Web" / "next.config.mjs",
]
TRANSACTIONS_PAGE = FE_WEB_SRC / "app" / "transactions" / "page.tsx"
DASHBOARD_PAGE = FE_WEB_SRC / "app" / "dashboard" / "page.tsx"


# All frontend source directories to scan
ALL_SRC_DIRS: List[Path] = [d for d in [FE_WEB_SRC, DASHBOARD_SRC] if d.exists()]

FRONTEND_EXTENSIONS = {".tsx", ".ts", ".js", ".jsx"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_files(
    root: Path,
    extensions: set | None = None,
    exclude_dirs: set | None = None,
) -> List[Path]:
    """Recursively collect files under *root* matching *extensions*."""
    extensions = extensions or FRONTEND_EXTENSIONS
    exclude_dirs = exclude_dirs or {"node_modules", ".next", "dist", "build", "__pycache__"}
    results: List[Path] = []
    if not root.exists():
        return results
    for dirpath, dirnames, filenames in os.walk(root):
        # prune excluded directories in-place
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fname in filenames:
            if Path(fname).suffix in extensions:
                results.append(Path(dirpath) / fname)
    return results


def _collect_all_frontend_files() -> List[Path]:
    """Return every frontend source file across all source dirs."""
    files: List[Path] = []
    for src_dir in ALL_SRC_DIRS:
        files.extend(_collect_files(src_dir))
    return files


def _search_files(
    files: List[Path],
    pattern: str | re.Pattern,
    *,
    flags: int = 0,
) -> List[Tuple[Path, int, str]]:
    """Return ``(path, lineno, line)`` for every matching line."""
    if isinstance(pattern, str):
        pattern = re.compile(pattern, flags)
    hits: List[Tuple[Path, int, str]] = []
    for fpath in files:
        try:
            text = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                hits.append((fpath, idx, line.strip()))
    return hits


def _read_next_config() -> str:
    """Return the contents of the Next.js config file (first one found)."""
    for candidate in NEXT_CONFIG_CANDIDATES:
        if candidate.exists():
            return candidate.read_text(encoding="utf-8", errors="ignore")
    pytest.skip("No next.config.{ts,js,mjs} found")
    return ""  # unreachable


# ========================================================================
# XSS Prevention Tests
# ========================================================================

class TestXSSPrevention:
    """Static checks for common XSS attack surfaces."""

    # ---- dangerouslySetInnerHTML -----------------------------------------

    def test_no_dangerouslySetInnerHTML_in_transactions(self):
        """transactions/page.tsx must not use dangerouslySetInnerHTML (even obfuscated)."""
        if not TRANSACTIONS_PAGE.exists():
            pytest.skip(f"{TRANSACTIONS_PAGE} not found")
        content = TRANSACTIONS_PAGE.read_text(encoding="utf-8", errors="ignore")
        # Detect both the literal prop *and* the obfuscated string-concat form
        patterns = [
            r"dangerouslySetInnerHTML",
            r"""\[\s*["']dangerously["']\s*\+""",      # ["dangerously" + …
            r"""__html""",                              # { __html: … }
        ]
        violations: List[str] = []
        for pat in patterns:
            for m in re.finditer(pat, content):
                lineno = content[: m.start()].count("\n") + 1
                violations.append(f"  line {lineno}: {content.splitlines()[lineno-1].strip()}")
        assert not violations, (
            "CRITICAL XSS: transactions/page.tsx contains dangerouslySetInnerHTML "
            "(including obfuscated variants):\n" + "\n".join(violations)
        )

    def test_no_dangerouslySetInnerHTML_in_dashboard(self):
        """dashboard/page.tsx must not use dangerouslySetInnerHTML (even obfuscated)."""
        if not DASHBOARD_PAGE.exists():
            pytest.skip(f"{DASHBOARD_PAGE} not found")
        content = DASHBOARD_PAGE.read_text(encoding="utf-8", errors="ignore")
        patterns = [
            r"dangerouslySetInnerHTML",
            r"""\[\s*["']dangerously["']\s*\+""",
            r"""__html""",
        ]
        violations: List[str] = []
        for pat in patterns:
            for m in re.finditer(pat, content):
                lineno = content[: m.start()].count("\n") + 1
                violations.append(f"  line {lineno}: {content.splitlines()[lineno-1].strip()}")
        assert not violations, (
            "CRITICAL XSS: dashboard/page.tsx contains dangerouslySetInnerHTML "

            "(including obfuscated variants):\n" + "\n".join(violations)
        )

    def test_no_dangerouslySetInnerHTML_in_components(self):
        """No .tsx component anywhere should use dangerouslySetInnerHTML."""
        files = _collect_all_frontend_files()
        # broad pattern: catches literal + obfuscated
        pat = re.compile(
            r"dangerouslySetInnerHTML|"
            r"""\[\s*["']dangerously["']\s*\+|"""
            r"""__html\s*:"""
        )
        hits = _search_files(files, pat)
        assert not hits, (
            f"CRITICAL XSS: dangerouslySetInnerHTML found in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:20])
        )

    # ---- innerHTML -------------------------------------------------------

    def test_no_innerHTML_assignments(self):
        """Direct .innerHTML assignments bypass React's escaping."""
        files = _collect_all_frontend_files()
        # Match  el.innerHTML = …  but ignore React's dangerouslySetInnerHTML (caught above)
        pat = re.compile(r"\.\s*innerHTML\s*=")
        hits = _search_files(files, pat)
        assert not hits, (
            f"XSS risk: direct innerHTML assignment in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:20])
        )

    # ---- eval ------------------------------------------------------------

    def test_no_eval_usage(self):
        """eval() enables arbitrary code execution from user input."""
        files = _collect_all_frontend_files()
        # Avoid false positives from comments / strings mentioning "eval"
        pat = re.compile(r"\beval\s*\(")
        hits = _search_files(files, pat)
        # Filter out test files and comments
        real_hits = [
            h for h in hits
            if not h[2].lstrip().startswith("//") and not h[2].lstrip().startswith("*")
            and ".test." not in str(h[0]) and ".spec." not in str(h[0])
        ]
        assert not real_hits, (
            f"CRITICAL: eval() usage found in {len(real_hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in real_hits[:20])
        )

    # ---- document.write --------------------------------------------------

    def test_no_document_write(self):
        """document.write() can introduce XSS and clobber the DOM."""
        files = _collect_all_frontend_files()
        pat = re.compile(r"document\s*\.\s*write\s*\(")
        hits = _search_files(files, pat)
        assert not hits, (
            f"XSS risk: document.write() found in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:20])
        )

    # ---- jQuery .html() -------------------------------------------------

    def test_no_jquery_html(self):
        """$().html() with user data is an XSS vector."""
        files = _collect_all_frontend_files()
        # Matches  $(...).html(  or  jQuery(...).html(
        pat = re.compile(r"(\$|jQuery)\s*\([^)]*\)\s*\.\s*html\s*\(")
        hits = _search_files(files, pat)
        assert not hits, (
            f"XSS risk: jQuery .html() found in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:20])
        )

    # ---- input maxLength -------------------------------------------------

    def test_input_fields_have_maxlength(self):
        """All <input> fields should specify maxLength to limit input size."""
        files = _collect_all_frontend_files()
        input_pat = re.compile(r"<input\b", re.IGNORECASE)
        maxlen_pat = re.compile(r"maxLength\s*=|maxlength\s*=", re.IGNORECASE)

        violations: List[Tuple[Path, int, str]] = []
        for fpath in files:
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            lines = text.splitlines()
            for idx, line in enumerate(lines, start=1):
                if input_pat.search(line):
                    # Collect the full JSX element (may span multiple lines)
                    element_text = line
                    j = idx
                    # simple heuristic: gather until we find '>' or '/>'
                    while j < len(lines) and not re.search(r"/\s*>|(?<!-)>", element_text):
                        j += 1
                        element_text += " " + lines[j - 1]
                    # Hidden / submit / checkbox / radio don't need maxLength
                    type_match = re.search(r'type\s*=\s*["\'](\w+)["\']', element_text, re.IGNORECASE)
                    skip_types = {"hidden", "submit", "checkbox", "radio", "button", "file", "image", "reset"}
                    if type_match and type_match.group(1).lower() in skip_types:
                        continue
                    if not maxlen_pat.search(element_text):
                        violations.append((fpath, idx, line.strip()))

        # Report as warning-level; many UI frameworks handle this via validation
        if violations:
            pytest.xfail(
                f"Input fields without maxLength in {len(violations)} location(s) "
                "(low severity, may be handled by validation):\n"
                + "\n".join(f"  {v[0].relative_to(PROJECT_ROOT)}:{v[1]}" for v in violations[:10])
            )

    # ---- javascript: protocol in hrefs -----------------------------------

    def test_no_user_data_in_href(self):
        """Links must not use javascript: protocol (XSS vector)."""
        files = _collect_all_frontend_files()
        pat = re.compile(r"""href\s*=\s*["']javascript:""", re.IGNORECASE)
        hits = _search_files(files, pat)
        assert not hits, (
            f"XSS risk: javascript: protocol in href found in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:20])
        )

    # ---- Unsafe template literals ----------------------------------------

    def test_no_unescaped_template_literals(self):
        """Template literals injected into HTML strings without escaping are XSS vectors."""
        files = _collect_all_frontend_files()
        # Pattern: innerHTML/outerHTML assigned a template literal, or
        # template literal containing <script / on-event handlers from variables
        pat = re.compile(
            r"(?:innerHTML|outerHTML)\s*=\s*`"  # innerHTML = `...`
            r"|"
            r"`[^`]*\$\{[^}]+\}[^`]*(?:<\s*script|on\w+\s*=)"  # `...${x}...<script` or `...${x}...onclick=`
        )
        hits = _search_files(files, pat)
        assert not hits, (
            f"XSS risk: unsafe template literal in HTML context in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:20])
        )

    # ---- outerHTML -------------------------------------------------------

    def test_no_outerHTML_assignments(self):
        """outerHTML assignment is another DOM-based XSS vector."""
        files = _collect_all_frontend_files()
        pat = re.compile(r"\.\s*outerHTML\s*=")
        hits = _search_files(files, pat)
        assert not hits, (
            f"XSS risk: outerHTML assignment in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:20])
        )


# ========================================================================
# Authentication Security Tests
# ========================================================================

class TestAuthenticationSecurity:
    """Ensure authentication tokens and credentials are handled securely."""

    def test_no_tokens_in_localstorage_code(self):
        """Tokens stored in localStorage are accessible to XSS.

        The project should use httpOnly cookies or sessionStorage (with care),
        not localStorage.setItem('token', …).
        """
        files = _collect_all_frontend_files()
        pat = re.compile(
            r"localStorage\s*\.\s*setItem\s*\(\s*['\"](?:token|jwt|access_token|auth|session)['\"]",
            re.IGNORECASE,
        )
        hits = _search_files(files, pat)
        # Exclude the tokenStorage shim itself which *removes* from localStorage
        hits = [h for h in hits if "removeItem" not in h[2]]
        assert not hits, (
            f"AUTH RISK: tokens stored in localStorage in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:10])
        )

    def test_no_hardcoded_credentials(self):
        """Source code must not contain hardcoded passwords or secrets."""
        files = _collect_all_frontend_files()
        pat = re.compile(
            r"""(?:password|passwd|secret|api_?key|apikey|private_?key)\s*[:=]\s*["'][^"']{4,}["']""",
            re.IGNORECASE,
        )
        hits = _search_files(files, pat)
        # Filter out type definitions, interfaces, placeholder/example strings
        real_hits = [
            h for h in hits
            if not any(kw in h[2].lower() for kw in [
                "type ", "interface ", "placeholder", "example", "mock", "test",
                "// ", "/* ", "* ", "label", "name=", "htmlfor",
            ])
        ]
        assert not real_hits, (
            f"CRITICAL: hardcoded credentials in {len(real_hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in real_hits[:10])
        )

    def test_no_api_keys_in_client_code(self):
        """API keys / bearer tokens must not be embedded in client source."""
        files = _collect_all_frontend_files()
        patterns = [
            # Common API key patterns
            r"""["'](?:sk|pk|api|key|bearer)[-_](?:live|test|prod)[a-zA-Z0-9]{10,}["']""",
            # AWS-style keys
            r"""["']AKIA[A-Z0-9]{16}["']""",
            # Generic long hex/base64 secrets assigned to key-like variables
            r"""(?:API_KEY|SECRET_KEY|AUTH_TOKEN)\s*[:=]\s*["'][a-zA-Z0-9+/=]{20,}["']""",
        ]
        all_hits: List[Tuple[Path, int, str]] = []
        for p in patterns:
            all_hits.extend(_search_files(files, p, flags=re.IGNORECASE))
        assert not all_hits, (
            f"CRITICAL: API keys exposed in client code in {len(all_hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in all_hits[:10])
        )

    def test_httponly_cookie_usage(self):
        """Client-set auth cookies should ideally be httpOnly (server-set).

        If the client sets cookies with ``document.cookie``, they CANNOT be
        httpOnly. The recommended pattern is to have the *server* set the
        cookie with the HttpOnly flag.
        """
        files = _collect_all_frontend_files()
        pat = re.compile(
            r"document\s*\.\s*cookie\s*=\s*.*(?:token|jwt|session|auth)",
            re.IGNORECASE,
        )
        hits = _search_files(files, pat)
        if hits:
            # This is expected in the tokenStorage shim — flag as a known issue
            pytest.xfail(
                f"Auth cookies set via document.cookie (cannot be HttpOnly) "
                f"in {len(hits)} location(s). Server should set HttpOnly cookies instead:\n"
                + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:5])
            )

    def test_secure_cookie_usage(self):
        """Cookies must include the Secure flag so they're only sent over HTTPS."""
        files = _collect_all_frontend_files()
        cookie_set_pat = re.compile(r"document\s*\.\s*cookie\s*=")
        secure_pat = re.compile(r"[Ss]ecure")

        violations: List[Tuple[Path, int, str]] = []
        for fpath in files:
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                if cookie_set_pat.search(line):
                    # Gather multi-line template literal or concatenation
                    context = line
                    if not secure_pat.search(context):
                        violations.append((fpath, idx, line.strip()))

        assert not violations, (
            f"AUTH RISK: cookies without Secure flag in {len(violations)} location(s):\n"
            + "\n".join(f"  {v[0].relative_to(PROJECT_ROOT)}:{v[1]}  {v[2]}" for v in violations[:10])
        )

    def test_no_jwt_decode_without_verify(self):
        """Client-side JWT decoding without verification can lead to trust issues."""
        files = _collect_all_frontend_files()
        # Catches  atob(token.split('.')[1])  pattern or jwt_decode without verify
        pat = re.compile(r"atob\s*\(\s*.*split\s*\(\s*['\"]\\?\.['\"]|jwt_decode\s*\(", re.IGNORECASE)
        hits = _search_files(files, pat)
        if hits:
            pytest.xfail(
                f"Client decodes JWT payload without verification in {len(hits)} location(s):\n"
                + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:5])
            )


# ========================================================================
# CSP & Security Headers Tests
# ========================================================================

class TestCSPSecurityHeaders:
    """Verify that security headers are properly configured in next.config."""

    @pytest.fixture()
    def config_text(self) -> str:
        return _read_next_config()

    def test_nextjs_security_headers(self, config_text: str):
        """next.config must define security headers (CSP, X-Frame-Options, etc.)."""
        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ]
        missing = [h for h in required_headers if h not in config_text]
        assert not missing, (
            f"Missing security headers in next.config: {', '.join(missing)}"
        )

    def test_no_unsafe_inline_csp(self, config_text: str):
        """CSP should not contain 'unsafe-inline' as it defeats XSS protection."""
        # Extract CSP value
        csp_match = re.search(
            r"""Content-Security-Policy.*?['"]([^'"]+)['"]""",
            config_text,
            re.DOTALL,
        )
        if not csp_match:
            pytest.skip("CSP header not found in config")
        csp_value = csp_match.group(1)
        assert "'unsafe-inline'" not in csp_value, (
            f"CRITICAL: CSP contains 'unsafe-inline' which defeats XSS protection. "
            f"Use nonces or hashes instead.\nCurrent CSP: {csp_value}"
        )

    def test_no_unsafe_eval_csp(self, config_text: str):
        """CSP should not contain 'unsafe-eval' as it allows eval()."""
        csp_match = re.search(
            r"""Content-Security-Policy.*?['"]([^'"]+)['"]""",
            config_text,
            re.DOTALL,
        )
        if not csp_match:
            pytest.skip("CSP header not found in config")
        csp_value = csp_match.group(1)
        assert "'unsafe-eval'" not in csp_value, (
            f"CRITICAL: CSP contains 'unsafe-eval' which allows eval() and similar. "
            f"Current CSP: {csp_value}"
        )

    def test_frame_ancestors_configured(self, config_text: str):
        """CSP frame-ancestors or X-Frame-Options must be set to prevent clickjacking."""
        has_frame_ancestors = "frame-ancestors" in config_text
        has_xframe = "X-Frame-Options" in config_text
        assert has_frame_ancestors or has_xframe, (
            "Clickjacking protection missing: neither frame-ancestors in CSP "
            "nor X-Frame-Options header is configured"
        )

    def test_referrer_policy_configured(self, config_text: str):
        """Referrer-Policy must be configured to prevent URL leakage."""
        assert "Referrer-Policy" in config_text, (
            "Referrer-Policy header is not configured in next.config. "
            "Recommended: 'strict-origin-when-cross-origin' or 'no-referrer'"
        )

    def test_strict_transport_security(self, config_text: str):
        """HSTS header should be present to enforce HTTPS."""
        if "Strict-Transport-Security" not in config_text:
            pytest.xfail(
                "Strict-Transport-Security (HSTS) header not set in next.config. "
                "Recommended: 'max-age=31536000; includeSubDomains'"
            )

    def test_permissions_policy_configured(self, config_text: str):
        """Permissions-Policy (formerly Feature-Policy) should restrict browser features."""
        if "Permissions-Policy" not in config_text and "Feature-Policy" not in config_text:
            pytest.xfail(
                "Permissions-Policy header not set. Consider restricting camera, "
                "microphone, geolocation, etc."
            )

    def test_nextjs_powered_by_header_disabled(self, config_text: str):
        """next.config must disable poweredByHeader to prevent fingerprinting."""
        assert "poweredByHeader" in config_text, (
            "poweredByHeader is not configured in next.config"
        )
        assert re.search(r"poweredByHeader\s*:\s*false", config_text), (
            "poweredByHeader is not set to false in next.config"
        )



# ========================================================================
# Sensitive Data Exposure Tests
# ========================================================================

class TestSensitiveDataExposure:
    """Ensure no sensitive data leaks through logs, source maps, or debug code."""

    def test_no_console_log_sensitive_data(self):
        """console.log must not log tokens, passwords, or sensitive user data."""
        files = _collect_all_frontend_files()
        pat = re.compile(
            r"console\s*\.\s*(?:log|info|debug|warn)\s*\("
            r"[^)]*(?:token|password|secret|credential|apiKey|authorization|jwt)",
            re.IGNORECASE,
        )
        hits = _search_files(files, pat)
        # Exclude test files
        hits = [h for h in hits if ".test." not in str(h[0]) and ".spec." not in str(h[0])]
        assert not hits, (
            f"DATA LEAK: console.log with sensitive data in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:10])
        )

    def test_no_hardcoded_api_urls_in_client(self):
        """API base URLs should come from environment variables, not hardcoded strings."""
        files = _collect_all_frontend_files()
        # Match hardcoded http(s):// URLs to API endpoints (not localhost which is dev)
        pat = re.compile(
            r"""["']https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"']+/api[/"']""",
            re.IGNORECASE,
        )
        hits = _search_files(files, pat)
        # Filter out comments
        hits = [h for h in hits if not h[2].lstrip().startswith("//")]
        assert not hits, (
            f"Hardcoded API URLs in client code (should use env vars) in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:10])
        )

    def test_source_maps_disabled_in_prod(self):
        """Production builds should not expose source maps."""
        config_text = _read_next_config()
        # next.config can enable source maps via productionBrowserSourceMaps
        if "productionBrowserSourceMaps" in config_text:
            match = re.search(r"productionBrowserSourceMaps\s*:\s*(true)", config_text)
            assert not match, (
                "Source maps are enabled in production! This exposes original source code. "
                "Set productionBrowserSourceMaps: false"
            )

        # Also check for devtool: 'source-map' in any webpack config
        files = _collect_all_frontend_files()
        pat = re.compile(r"""devtool\s*:\s*['"]source-map['"]""")
        hits = _search_files(files, pat)
        assert not hits, (
            f"Source maps enabled via devtool in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:5])
        )

    def test_error_boundaries_exist(self):
        """React error boundaries prevent stack trace leakage to users."""
        files = _collect_all_frontend_files()
        all_content = ""
        for f in files:
            try:
                all_content += f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

        has_error_boundary = (
            "ErrorBoundary" in all_content
            or "componentDidCatch" in all_content
            or "error.tsx" in " ".join(str(f) for f in files)
            or "error.jsx" in " ".join(str(f) for f in files)
            # Next.js app router has built-in error.tsx support
            or any(f.name in ("error.tsx", "error.jsx", "error.js") for f in files)
        )
        if not has_error_boundary:
            pytest.xfail(
                "No React error boundary found. Add an ErrorBoundary component "
                "or Next.js error.tsx to prevent stack traces leaking to users."
            )

    def test_no_debug_mode_in_prod(self):
        """Debug flags / modes should not be enabled in production code."""
        files = _collect_all_frontend_files()
        patterns = [
            r"""["']debug["']\s*:\s*true""",
            r"DEBUG\s*=\s*true",
            r"enableDebug\s*[:=]\s*true",
            r"REACT_APP_DEBUG\s*[:=]\s*true",
        ]
        all_hits: List[Tuple[Path, int, str]] = []
        for p in patterns:
            all_hits.extend(_search_files(files, p, flags=re.IGNORECASE))
        # Filter test files
        all_hits = [h for h in all_hits if ".test." not in str(h[0])]
        assert not all_hits, (
            f"Debug mode enabled in {len(all_hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in all_hits[:10])
        )

    def test_no_sensitive_data_in_error_messages(self):
        """Error messages displayed to users should not contain stack traces or SQL."""
        files = _collect_all_frontend_files()
        # Check for raw error.stack or error.message rendered directly
        pat = re.compile(
            r"""(?:sqlErrorDetails|stackTrace|error\.stack)\s*(?:\}|&&)""",
        )
        hits = _search_files(files, pat)
        if hits:
            pytest.xfail(
                f"Potential stack trace / SQL error exposure in {len(hits)} location(s):\n"
                + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:5])
            )

    def test_no_verbose_error_rendering(self):
        """Frontend should not render verbose database error details to users."""
        files = _collect_all_frontend_files()
        pat = re.compile(r"sqlErrorDetails|DATABASE STACK TRACE", re.IGNORECASE)
        hits = _search_files(files, pat)
        assert not hits, (
            f"INFORMATION DISCLOSURE: verbose DB error rendering in {len(hits)} location(s):\n"
            + "\n".join(f"  {h[0].relative_to(PROJECT_ROOT)}:{h[1]}  {h[2]}" for h in hits[:10])
        )
