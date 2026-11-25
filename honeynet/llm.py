"""The only file that talks to the model.

Any OpenAI-compatible chat API. Settings come from the environment or a .env file:
    LLM_BASE_URL   e.g. https://api.example.com/v1
    LLM_API_KEY
    LLM_MODEL      (LLM_MODEL_<STEP> overrides it for one step, e.g. LLM_MODEL_PCAP_VERDICT)

Uses only the standard library, so there is nothing extra to install.
TODO: retries, a disk cache, and a tool-using agent loop (run_agent).
"""
import json
import os
import ssl
import urllib.error
import urllib.request

from .config import REPO_ROOT

try:
    from dotenv import load_dotenv
    load_dotenv(REPO_ROOT / ".env")
except ImportError:
    pass


def _ssl_context():
    """python.org builds on macOS ship without root certificates; certifi has them."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return None


def model_for(step):
    return os.getenv(f"LLM_MODEL_{step.upper()}") or os.getenv("LLM_MODEL", "")


def configured(step):
    return bool(os.getenv("LLM_BASE_URL") and os.getenv("LLM_API_KEY") and model_for(step))


def check(step="pcap_verdict"):
    """Test the settings with one tiny request. Prints what it finds, never the key. Returns True if it works."""
    base, key, model = os.getenv("LLM_BASE_URL", ""), os.getenv("LLM_API_KEY", ""), model_for(step)
    print(f"LLM_BASE_URL: {base or 'MISSING'}")
    print(f"LLM_API_KEY:  {'set (' + str(len(key)) + ' characters)' if key else 'MISSING'}")
    print(f"LLM_MODEL:    {model or 'MISSING'}")
    if not (base and key and model):
        print(f"\nFill in the missing values in {REPO_ROOT / '.env'} (see .env.example).")
        return False
    try:
        reply = chat(step, "Reply with the single word: ok", "ping", timeout=60)
    except urllib.error.HTTPError as e:
        hints = {401: "the key is wrong or expired", 403: "the key is not allowed to use this model",
                 404: "wrong LLM_BASE_URL (it usually ends in /v1) or wrong model name",
                 429: "rate limited, wait a bit and retry"}
        print(f"\nFAILED: HTTP {e.code}, {hints.get(e.code, 'see the message below')}")
        print(e.read().decode(errors="replace")[:300])
        return False
    except Exception as e:
        print(f"\nFAILED: {type(e).__name__}: {e}")
        return False
    print(f"\nOK. The model replied: {reply.strip()[:80]!r}")
    return True


def chat(step, system, user, timeout=300):
    """Send one system+user message, return the model's text reply."""
    url = os.environ["LLM_BASE_URL"].rstrip("/")
    if not url.endswith("/chat/completions"):  # accept either the base URL or the full endpoint
        url += "/chat/completions"
    body = json.dumps({
        "model": model_for(step),
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0,
    }).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {os.environ['LLM_API_KEY']}"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
        return json.load(resp)["choices"][0]["message"]["content"]
