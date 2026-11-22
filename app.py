
import os
import sys
import joblib
import pandas as pd
import streamlit as st

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

import phishing_features as pf

MODEL_PATH = os.path.join(PROJECT_DIR, "phishing_model_25.pkl")

model_package = joblib.load(MODEL_PATH)
model = model_package["model"]
available_features = pf.available_features
collect_live_features_25 = pf.collect_live_features_25

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ PhishGuard AI")
st.subheader("AI-Powered Phishing Website Detection")

st.write(
    "Enter a website URL below to analyze its characteristics "
    "and predict whether it is potentially phishing or legitimate."
)

url = st.text_input(
    "Enter Website URL",
    placeholder="https://example.com"
)

if st.button("🔍 Analyze Website", use_container_width=True):

    if not url.strip():
        st.warning("Please enter a website URL.")

    elif not url.strip().lower().startswith(("http://", "https://")):
        st.warning("Please enter a valid URL beginning with http:// or https://.")

    else:
        with st.spinner("Analyzing website..."):

            try:
                features = collect_live_features_25(url.strip())

                missing = [
                    name for name in available_features
                    if features.get(name) is None
                ]

                if missing:
                    st.error(
                        f"Analysis incomplete. {len(missing)} features "
                        "could not be extracted."
                    )
                    st.write("Missing features:", missing)

                else:
                    input_data = pd.DataFrame(
                        [[features[name] for name in available_features]],
                        columns=available_features
                    )

                    prediction = model.predict(input_data)[0]

                    st.divider()
                    st.subheader("Detection Result")

                    if prediction == -1:
                        st.error("⚠️ Potential Phishing Website")
                    else:
                        st.success("✅ Likely Legitimate Website")

                    st.write("Prediction:", int(prediction))
                    st.caption(
                        "This is an automated ML prediction, not a "
                        "guarantee of website safety."
                    )

            except Exception as e:
                st.error(f"Analysis failed: {e}")

st.divider()
st.caption("Powered by Random Forest Machine Learning")
