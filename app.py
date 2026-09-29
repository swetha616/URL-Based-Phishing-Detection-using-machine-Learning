import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
from datetime import datetime
from feature_extractor import extract_features

st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="wide")

# ---------- Load Model ----------
@st.cache_resource
def load_model():
    return joblib.load("phishing_model.pkl")

model = load_model()

# ---------- Session State ----------
if "history" not in st.session_state:
    st.session_state.history = []

# ---------- Header ----------
st.title("🛡️ Real-Time Phishing URL Detector")
st.caption("Paste a URL below — the model predicts instantly using 27 URL features.")

# ---------- Tabs ----------
tab1, tab2, tab3 = st.tabs(["🔍 Detect", "📊 Dashboard", "📖 About"])

# ================= TAB 1: DETECT =================
with tab1:
    col1, col2 = st.columns([3, 1])
    with col1:
        url = st.text_input("Enter URL", placeholder="https://example.com/login")
    with col2:
        st.write("")
        st.write("")
        scan = st.button("🚀 Scan", use_container_width=True, type="primary")

    if scan and url:
        try:
            feats = extract_features(url)

            # ⭐ WHITELIST OVERRIDE — force LEGIT for known-good domains
            if feats.get('is_whitelisted', 0) == 1:
                pred = 0
                prob = 0.01  # low phishing probability
                st.success(f"✅ **LEGITIMATE** — Whitelisted top domain")
                result_label = "LEGIT (whitelisted)"
            else:
                X = pd.DataFrame([feats])
                if hasattr(model, 'feature_names_in_'):
                    X = X[model.feature_names_in_]
                pred = int(model.predict(X)[0])
                prob = float(model.predict_proba(X)[0][1])

                if pred == 1:
                    st.error(f"🚨 **PHISHING DETECTED** — Confidence: {prob*100:.2f}%")
                    result_label = "PHISHING"
                else:
                    st.success(f"✅ **LEGITIMATE** — Confidence: {(1-prob)*100:.2f}%")
                    result_label = "LEGIT"

            # Feature breakdown
            st.subheader("🔬 Feature Breakdown")
            fdf = pd.DataFrame(list(feats.items()), columns=["Feature", "Value"])
            st.dataframe(fdf, use_container_width=True, hide_index=True)

            # Save to history
            st.session_state.history.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "url": url,
                "result": "PHISHING" if pred == 1 else "LEGIT",
                "confidence": round(prob if pred == 1 else 1 - prob, 4),
                "prob_phish": round(prob, 4),
            })
        except Exception as e:
            st.warning(f"Could not analyze URL: {e}")

# ================= TAB 2: DASHBOARD =================
with tab2:
    hist = st.session_state.history
    if not hist:
        st.info("No scans yet. Go to the 'Detect' tab and try a URL.")
    else:
        hdf = pd.DataFrame(hist)
        total = len(hdf)
        phish_n = (hdf["result"] == "PHISHING").sum()
        legit_n = total - phish_n

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Scans", total)
        c2.metric("🚨 Phishing", phish_n)
        c3.metric("✅ Legit", legit_n)
        c4.metric("Detection Rate", f"{phish_n/total*100:.1f}%" if total else "0%")

        col_a, col_b = st.columns(2)
        with col_a:
            fig = px.pie(
                names=["Legit", "Phishing"],
                values=[legit_n, phish_n],
                color=["Legit", "Phishing"],
                color_discrete_map={"Legit": "#22c55e", "Phishing": "#ef4444"},
                title="Result Distribution",
            )
            st.plotly_chart(fig, use_container_width=True)
        with col_b:
            fig2 = px.histogram(
                hdf, x="prob_phish", nbins=20,
                title="Phishing Probability Distribution",
                color_discrete_sequence=["#6366f1"],
            )
            st.plotly_chart(fig2, use_container_width=True)

        st.subheader("📈 Detection Timeline")
        fig3 = px.scatter(
            hdf, x="time", y="prob_phish", color="result",
            color_discrete_map={"LEGIT": "#22c55e", "PHISHING": "#ef4444"},
            title="Phishing Probability Over Time",
        )
        fig3.update_yaxes(range=[0, 1], title="Phishing Probability")
        st.plotly_chart(fig3, use_container_width=True)

        st.subheader("📋 Scan History")
        st.dataframe(hdf, use_container_width=True, hide_index=True)

        st.download_button(
            "⬇️ Download CSV",
            hdf.to_csv(index=False),
            "scan_history.csv",
            "text/csv",
        )

# ================= TAB 3: ABOUT =================
with tab3:
    st.markdown("""
    ### 🎯 What this does
    Detects whether a URL is **phishing** or **legitimate** in real time using a
    Random Forest classifier trained on **44,000+ labeled URLs**.

    ### 🧠 Model
    - **Algorithm:** Random Forest (200 trees, max_depth=20)
    - **Features:** **27 URL-based features** (lexical + structural + typosquat-aware)
    - **Training data:** 20k PhishTank + 20k Tranco + 3k+ synthetic typosquats
    - **Test accuracy:** 96.7% on held-out split, 30/30 on curated test set

    ### 📊 Feature Categories
    - **Length:** `url_length`, `host_length`, `path_length`
    - **Character counts:** `num_dots`, `num_hyphens`, `num_digits`, `num_special`
    - **Structural:** `has_ip`, `has_at`, `is_https`, `num_subdomains`, `has_port`
    - **Statistical:** `entropy`, `digit_ratio`, `special_ratio`
    - **Security heuristics:** `suspicious_tld`, `shortener`, `brand_in_subdomain`
    - **Typosquat-aware:** `min_brand_dist` (Levenshtein), `homoglyph_brand_match`,
      `is_exact_brand`, `is_whitelisted`

    ### 🔬 Typosquatting Detection
    - **Levenshtein distance** to known brands (hyphen-split aware)
    - **Homoglyph normalization** (`0→o`, `1→l`, `3→e`, `@→a`)
    - **Synthetic typosquat augmentation** with 3,000+ generated samples

    ### 🛡️ Whitelist Safeguard
    Top-ranked legitimate domains (e.g., `google.com`, `wikipedia.org`) are
    always classified as LEGIT to prevent false positives — a defense-in-depth
    pattern used in Chrome Safe Browsing and Microsoft SmartScreen.

    ### ⚡ Deployment
    Runs locally with **sub-2ms inference** — suitable for browser extensions
    and edge devices.
    """)
