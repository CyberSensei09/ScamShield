
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "scam_model.joblib"

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="centered"
)


@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH)


def extract_urls(message):
    # Find URLs without visiting them
    return re.findall(
        r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""",
        message
    )


def check_url(url):
    findings = []

    cleaned = url.rstrip(".,!?;:)")
    candidate = cleaned if cleaned.lower().startswith(
        ("http://", "https://")
    ) else "https://" + cleaned

    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
    except ValueError:
        return ["URL could not be parsed"]

    host = host.lower()

    if not host or "." not in host:
        findings.append("Unusual or incomplete domain")

    if parsed.scheme.lower() == "http":
        findings.append("Uses unencrypted HTTP")

    if "@" in parsed.netloc:
        findings.append("Contains an @ sign in the URL")

    if host.startswith("xn--") or ".xn--" in host:
        findings.append("Contains an internationalized domain")

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        findings.append("Uses an IP address instead of a domain")

    if len(host) > 45:
        findings.append("Unusually long domain")

    if len(re.findall(r"\.", host)) >= 4:
        findings.append("Many subdomains")

    if not findings:
        findings.append(
            "No basic URL warning pattern detected; "
            "this does not prove the link is safe."
        )

    return findings


st.title("🛡️ ScamShield AI")
st.caption("Machine-learning SMS screening and suspicious-link checks")

st.info(
    "Paste a message below. ScamShield checks learned text patterns "
    "and basic URL warning signs. It does not guarantee safety."
)

message = st.text_area(
    "Message to scan",
    placeholder="Paste your SMS, email text, or message here...",
    height=160
)

if st.button("🔍 Scan Message", type="primary", use_container_width=True):
    if not message.strip():
        st.warning("Please enter a message first.")
    else:
        try:
            model = load_model()

            prediction = model.predict([message])[0]
            classes = list(
                model.named_steps["classifier"].classes_
            )
            probabilities = model.predict_proba([message])[0]
            spam_score = float(
                probabilities[classes.index("spam")]
            )

            st.subheader("Scan result")

            if prediction == "spam":
                st.error("⚠️ Classified as spam-like / suspicious")
            else:
                st.success("Classified as likely legitimate")

            st.metric("Model spam score", f"{spam_score:.1%}")

            st.caption(
                "The score is the model's estimated spam probability, "
                "not a verified probability of fraud."
            )

            # Explain simple warning signs separately from ML output
            lower = message.lower()
            warning_terms = [
                "otp", "password", "urgent", "blocked",
                "verify", "claim your prize", "won a prize",
                "account suspended", "send money", "kyc"
            ]

            found = [
                term for term in warning_terms if term in lower
            ]

            st.subheader("Potential warning signs")
            if found:
                st.write(
                    "Terms to review: " + ", ".join(found)
                )
            else:
                st.write(
                    "No terms from the basic warning list were found. "
                    "Other warning signs may still exist."
                )

            urls = extract_urls(message)
            st.subheader("Suspicious-link checks")

            if not urls:
                st.write("No obvious HTTP/HTTPS or www link found.")
            else:
                for url in urls:
                    st.write(f"**Link found:** `{url}`")
                    findings = check_url(url)
                    for finding in findings:
                        st.write(f"- {finding}")

            st.warning(
                "Never share OTPs, UPI PINs, passwords, or bank "
                "credentials in response to an unsolicited message. "
                "Verify requests using official channels."
            )

        except FileNotFoundError:
            st.error(
                "Model file not found. Check that "
                "models/scam_model.joblib exists in the repository."
            )
        except Exception as error:
            st.error(f"Unable to scan the message: {error}")

st.divider()
st.caption(
    "ScamShield is a prototype. Basic URL checks are not a live "
    "reputation lookup, and a low-risk result does not prove safety."
)
