import logging
import os
import sys
import time
from datetime import datetime

import requests
from dotenv import load_dotenv

LOGIN_URL = "https://doms.iitm.ac.in/domsmba/index.php/admission/login_val"
SHORTLIST_URL = "https://doms.iitm.ac.in/domsmba/index.php/shortlist"
RESULT_URL = "https://doms.iitm.ac.in/domsmba/"

POLL_INTERVAL_SECONDS = 5 * 60
TRANSIENT_RETRY_SECONDS = 60
CONFIRM_DELAY_SECONDS = 30
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("doms_check.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("doms_bot")


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
    """Return (state, evidence). state in: not_live, live, login_page, waf, server_error, uncertain."""
    body_lower = (body or "").lower()
    size = len(body or "")

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


def login_and_fetch(email: str, password: str) -> tuple:
    """Returns (status, body, final_url, cookie_names_set)."""
    session = requests.Session()
    session.headers.update(
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

    login_resp = session.post(
        LOGIN_URL,
        data={"username": email, "password": password},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
    )
    cookie_names = {c.name for c in session.cookies}
    log.info("Login status=%s cookies=%s", login_resp.status_code, sorted(cookie_names))

    missing = EXPECTED_COOKIES - cookie_names
    if missing:
        log.warning("Missing expected cookies after login: %s", sorted(missing))

    resp = session.get(SHORTLIST_URL, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    body = resp.text or ""
    log.info("Shortlist status=%s length=%d final_url=%s", resp.status_code, len(body), resp.url)
    return resp.status_code, body, resp.url, cookie_names


def confirm_live(email: str, password: str) -> tuple:
    """Run a second check after a delay. Both must classify as 'live' to confirm."""
    log.info("Possible LIVE — confirming with second check in %ds...", CONFIRM_DELAY_SECONDS)
    time.sleep(CONFIRM_DELAY_SECONDS)
    status, body, final_url, cookies = login_and_fetch(email, password)
    state, evidence = classify(status, body, final_url, cookies)
    log.info("Confirmation check state=%s evidence=%s", state, evidence)
    return state, evidence, body[:500]


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
        f"Polling every {POLL_INTERVAL_SECONDS // 60} min. Foolproof detection mode."
    )
    log.info(startup_msg)
    send_telegram(token, chat_ids, startup_msg)

    live_alert_sent = False
    consecutive_login_problems = 0
    consecutive_waf_problems = 0
    consecutive_uncertain = 0
    notified_login_problem = False
    notified_waf_problem = False
    last_uncertain_alert_at = 0.0

    while True:
        sleep_for = POLL_INTERVAL_SECONDS
        try:
            status, body, final_url, cookies = login_and_fetch(email, password)
            state, evidence = classify(status, body, final_url, cookies)
            log.info("Classification: state=%s evidence=%s", state, evidence)

            if state == "live":
                if live_alert_sent:
                    log.info("Still live; alert already sent.")
                else:
                    confirm_state, confirm_evidence, snippet = confirm_live(email, password)
                    if confirm_state == "live":
                        log.info("CONFIRMED LIVE. Sending alert.")
                        send_telegram(
                            token,
                            chat_ids,
                            f"🎉 IITM DoMS MBA Result is LIVE! Check now: {RESULT_URL}",
                        )
                        live_alert_sent = True
                    else:
                        log.warning(
                            "First check said live, second said %s (%s). Holding off, will recheck next cycle.",
                            confirm_state, confirm_evidence,
                        )
                        send_telegram(
                            token,
                            chat_ids,
                            (
                                "⚠️ DoMS bot saw a possibly-live response but the confirmation "
                                f"check disagreed (got: {confirm_state}). Will keep polling. "
                                f"First evidence: {evidence}"
                            ),
                        )

            elif state == "not_live":
                consecutive_login_problems = 0
                consecutive_waf_problems = 0
                consecutive_uncertain = 0
                notified_login_problem = False
                notified_waf_problem = False
                log.info("Page not live yet.")

            elif state == "server_error":
                log.warning("Server error (%s). Backing off briefly.", evidence)
                sleep_for = TRANSIENT_RETRY_SECONDS

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
                sleep_for = TRANSIENT_RETRY_SECONDS

            elif state == "login_page":
                consecutive_login_problems += 1
                log.error("Auth problem (%s) — count=%d", evidence, consecutive_login_problems)
                if consecutive_login_problems >= 3 and not notified_login_problem:
                    send_telegram(
                        token,
                        chat_ids,
                        "⚠️ DoMS bot login appears to be failing on 3 consecutive checks. "
                        "Verify DOMS_EMAIL / DOMS_PASSWORD env vars are correct.",
                    )
                    notified_login_problem = True

            elif state == "uncertain":
                consecutive_uncertain += 1
                log.warning("Uncertain response (%s).", evidence)
                now = time.time()
                if now - last_uncertain_alert_at > 3600 and consecutive_uncertain >= 2:
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
                    last_uncertain_alert_at = now

        except requests.RequestException as exc:
            log.error("Network error: %s", exc)
            sleep_for = TRANSIENT_RETRY_SECONDS
        except Exception as exc:
            log.exception("Unexpected error: %s", exc)
            sleep_for = TRANSIENT_RETRY_SECONDS

        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
