import logging
import os
import random
import sys
import time
from datetime import datetime

import requests
from dotenv import load_dotenv

LOGIN_URL = "https://doms.iitm.ac.in/domsmba/index.php/admission/login_val"
SHORTLIST_URL = "https://doms.iitm.ac.in/domsmba/index.php/shortlist"
RESULT_URL = "https://doms.iitm.ac.in/domsmba/"

POLL_INTERVAL_SECONDS = 10
POLL_JITTER_SECONDS = 2
SESSION_MAX_AGE_SECONDS = 90 * 60
TRANSIENT_BACKOFF_SECONDS = 60
RATE_LIMIT_BACKOFF_SECONDS = 120
CONFIRM_DELAY_SECONDS = 15
REQUEST_TIMEOUT = 30
MIN_LIVE_BODY_BYTES = 2000

EXPECTED_COOKIES = {"ci_session", "BNES_ci_session", "BNIS_x-bni-jas"}

NOT_LIVE_MARKERS = (
    "cannot be found",
    "specified url cannot be found",
    "page not found",
    "page does not exist",
    "404 not found",
    "404 page",
    "error 404",
    "the requested url",
    "not found on this server",
)

LOGIN_PAGE_MARKERS = (
    'name="username"',
    'name="password"',
    "admission/login",
    "forgot password",
    "invalid username",
    "invalid password",
    "login failed",
)

WAF_MARKERS = (
    "cloudflare",
    "attention required",
    "challenge-platform",
    "ddos protection",
    "access denied",
    "blocked by",
    "checking your browser",
)

POSITIVE_LIVE_MARKERS = (
    "shortlist",
    "candidate",
    "roll no",
    "roll number",
    "application no",
    "application number",
    "selected",
    "<table",
    "download",
    "name of the candidate",
)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, Exception):
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("doms_check.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("doms_bot")


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    return s


def login(session: requests.Session, email: str, password: str) -> set:
    resp = session.post(
        LOGIN_URL,
        data={"username": email, "password": password},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
    )
    cookie_names = {c.name for c in session.cookies}
    log.info("Login status=%s cookies=%s", resp.status_code, sorted(cookie_names))
    missing = EXPECTED_COOKIES - cookie_names
    if missing:
        log.warning("Missing expected cookies after login: %s", sorted(missing))
    return cookie_names


def fetch_shortlist(session: requests.Session) -> tuple:
    resp = session.get(SHORTLIST_URL, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    body = resp.text or ""
    cookie_names = {c.name for c in session.cookies}
    return resp.status_code, body, resp.url, cookie_names


def send_telegram(token: str, chat_ids: list, text: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for chat_id in chat_ids:
        try:
            r = requests.post(
                url,
                data={"chat_id": chat_id, "text": text},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                log.error("Telegram send to %s failed (%s): %s", chat_id, r.status_code, r.text[:200])
            else:
                log.info("Telegram message sent to %s.", chat_id)
        except requests.RequestException as exc:
            log.error("Telegram request error for %s: %s", chat_id, exc)


def classify(status: int, body: str, final_url: str, cookies_present: set) -> tuple:
    """Return (state, evidence). state in: not_live, live, login_page, waf, rate_limited, server_error, uncertain."""
    body_lower = (body or "").lower()
    size = len(body or "")

    if status == 429:
        return "rate_limited", "HTTP 429"

    if status >= 500:
        return "server_error", f"HTTP {status}"

    if any(m in body_lower for m in WAF_MARKERS):
        return "waf", "WAF/Cloudflare interference detected"

    if any(m in body_lower for m in NOT_LIVE_MARKERS):
        return "not_live", "negative marker in body"

    auth_lost = bool(EXPECTED_COOKIES - cookies_present)
    looks_like_login = any(m in body_lower for m in LOGIN_PAGE_MARKERS)
    if looks_like_login and (auth_lost or "login" in final_url.lower()):
        return "login_page", "shortlist response looks like login page (session/creds problem)"

    if status == 200:
        positive = [m for m in POSITIVE_LIVE_MARKERS if m in body_lower]
        if positive and size >= 800:
            return "live", f"status=200 size={size} positive_markers={positive[:5]}"
        if size >= MIN_LIVE_BODY_BYTES:
            return "uncertain", f"status=200 size={size} but no positive markers"
        return "uncertain", f"status=200 small body ({size} bytes), no positive markers"

    return "uncertain", f"status={status} size={size}"


def main() -> None:
    load_dotenv()
    email = os.getenv("DOMS_EMAIL")
    password = os.getenv("DOMS_PASSWORD")
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id_raw = os.getenv("TELEGRAM_CHAT_ID", "")
    chat_ids = [c.strip() for c in chat_id_raw.split(",") if c.strip()]

    missing = [k for k, v in {
        "DOMS_EMAIL": email,
        "DOMS_PASSWORD": password,
        "TELEGRAM_BOT_TOKEN": token,
        "TELEGRAM_CHAT_ID": chat_id_raw,
    }.items() if not v]
    if missing:
        log.error("Missing env vars: %s", ", ".join(missing))
        sys.exit(1)

    startup_msg = (
        f"✅ DoMS bot started at {datetime.now().isoformat(timespec='seconds')}. "
        f"Polling every ~{POLL_INTERVAL_SECONDS}s with persistent session "
        f"(re-login every {SESSION_MAX_AGE_SECONDS // 60} min). Foolproof detection mode."
    )
    log.info(startup_msg)
    send_telegram(token, chat_ids, startup_msg)

    session = None
    session_started_at = 0.0

    live_alert_sent = False
    pending_live_confirmation_at = 0.0
    pending_live_evidence = ""

    consecutive_login_problems = 0
    consecutive_waf_problems = 0
    consecutive_rate_limited = 0
    consecutive_uncertain = 0
    notified_login_problem = False
    notified_waf_problem = False
    last_uncertain_alert_at = 0.0
    last_state = None
    same_state_count = 0
    last_state_log_at = 0.0

    while True:
        sleep_for = POLL_INTERVAL_SECONDS + random.uniform(-POLL_JITTER_SECONDS, POLL_JITTER_SECONDS)
        try:
            now = time.time()
            need_relogin = (
                session is None
                or (now - session_started_at) >= SESSION_MAX_AGE_SECONDS
            )
            if need_relogin:
                log.info("Logging in (session age=%.0fs)...", now - session_started_at if session else 0)
                session = make_session()
                login(session, email, password)
                session_started_at = time.time()

            status, body, final_url, cookies = fetch_shortlist(session)
            state, evidence = classify(status, body, final_url, cookies)

            if state == last_state and state == "not_live":
                same_state_count += 1
                # log a heartbeat every ~5 min to keep the log readable but visible
                if (time.time() - last_state_log_at) >= 300:
                    log.info("Still not_live (x%d in a row).", same_state_count)
                    last_state_log_at = time.time()
            else:
                log.info("State=%s shortlist_status=%s size=%d evidence=%s",
                         state, status, len(body), evidence)
                last_state_log_at = time.time()
                same_state_count = 1
            last_state = state

            if state == "live":
                if live_alert_sent:
                    pass
                elif pending_live_confirmation_at == 0.0:
                    pending_live_confirmation_at = time.time() + CONFIRM_DELAY_SECONDS
                    pending_live_evidence = evidence
                    log.info("Possible LIVE detected — will confirm in %ds.", CONFIRM_DELAY_SECONDS)
                elif time.time() >= pending_live_confirmation_at:
                    log.info("CONFIRMED LIVE on second observation. Sending alert.")
                    send_telegram(
                        token,
                        chat_ids,
                        f"🎉 IITM DoMS MBA Result is LIVE! Check now: {RESULT_URL}",
                    )
                    live_alert_sent = True
                    pending_live_confirmation_at = 0.0
            else:
                if pending_live_confirmation_at > 0.0 and not live_alert_sent:
                    log.warning(
                        "Pending live confirmation aborted: state flipped to %s (%s). Original evidence: %s",
                        state, evidence, pending_live_evidence,
                    )
                    send_telegram(
                        token,
                        chat_ids,
                        (
                            "⚠️ DoMS bot saw a possibly-live response but the confirmation check "
                            f"disagreed (now: {state}). Holding off. Will keep polling."
                        ),
                    )
                    pending_live_confirmation_at = 0.0
                    pending_live_evidence = ""

            if state == "not_live":
                consecutive_login_problems = 0
                consecutive_waf_problems = 0
                consecutive_rate_limited = 0
                consecutive_uncertain = 0
                notified_login_problem = False
                notified_waf_problem = False

            elif state == "server_error":
                log.warning("Server error (%s). Backing off.", evidence)
                sleep_for = TRANSIENT_BACKOFF_SECONDS

            elif state == "rate_limited":
                consecutive_rate_limited += 1
                log.error("Rate limited (%s) — count=%d. Backing off %ds.",
                          evidence, consecutive_rate_limited, RATE_LIMIT_BACKOFF_SECONDS)
                sleep_for = RATE_LIMIT_BACKOFF_SECONDS * min(consecutive_rate_limited, 5)

            elif state == "waf":
                consecutive_waf_problems += 1
                log.error("WAF/block detected (%s) — count=%d", evidence, consecutive_waf_problems)
                if consecutive_waf_problems >= 3 and not notified_waf_problem:
                    send_telegram(
                        token,
                        chat_ids,
                        "⚠️ DoMS bot is being blocked by a WAF/Cloudflare page on 3 consecutive checks. "
                        "Manual login from a browser may be required to verify and clear the block.",
                    )
                    notified_waf_problem = True
                sleep_for = RATE_LIMIT_BACKOFF_SECONDS

            elif state == "login_page":
                consecutive_login_problems += 1
                log.error("Auth problem (%s) — count=%d. Forcing fresh login next cycle.",
                          evidence, consecutive_login_problems)
                session = None  # force re-login
                if consecutive_login_problems >= 5 and not notified_login_problem:
                    send_telegram(
                        token,
                        chat_ids,
                        "⚠️ DoMS bot login appears to be failing on 5 consecutive checks. "
                        "Verify DOMS_EMAIL / DOMS_PASSWORD env vars are correct.",
                    )
                    notified_login_problem = True

            elif state == "uncertain":
                consecutive_uncertain += 1
                log.warning("Uncertain response (%s).", evidence)
                if (time.time() - last_uncertain_alert_at) > 3600 and consecutive_uncertain >= 3:
                    snippet = (body or "")[:400].replace("\n", " ")
                    send_telegram(
                        token,
                        chat_ids,
                        (
                            "🤔 DoMS bot got an UNUSUAL response (not the standard 'not found' page, "
                            "but also not clearly the live results page). "
                            f"Evidence: {evidence}\n\nFirst 400 chars:\n{snippet}\n\n"
                            f"Visit manually to verify: {RESULT_URL}"
                        ),
                    )
                    last_uncertain_alert_at = time.time()

        except requests.RequestException as exc:
            log.error("Network error: %s", exc)
            session = None
            sleep_for = TRANSIENT_BACKOFF_SECONDS
        except Exception as exc:
            log.exception("Unexpected error: %s", exc)
            session = None
            sleep_for = TRANSIENT_BACKOFF_SECONDS

        time.sleep(max(1.0, sleep_for))


if __name__ == "__main__":
    main()
