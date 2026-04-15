import streamlit as st

# -------------------------------
# Page config
# -------------------------------
st.set_page_config(page_title="Cybersecurity Anomaly Dashboard", layout="wide")

# -------------------------------
# Sample model output
# Replace these later with real values if needed
# -------------------------------
score = 9.5787
alert_level = "MEDIUM"
alert_type = "Authentication Attack"

# -------------------------------
# Security level logic
# -------------------------------
if score < 5:
    security_level = "SAFE"
elif score <= 10:
    security_level = "SUSPICIOUS"
else:
    security_level = "CRITICAL"

# -------------------------------
# Sidebar guide
# -------------------------------
st.sidebar.title("Security Level Guide")
st.sidebar.success("SAFE\n\nScore < 5")
st.sidebar.warning("SUSPICIOUS\n\nScore 5 - 10")
st.sidebar.error("CRITICAL\n\nScore > 10")
st.sidebar.info("This guide helps users understand the risk level based on anomaly score.")

# -------------------------------
# Main title
# -------------------------------
st.title("Cybersecurity Anomaly Detection Dashboard")

# -------------------------------
# Top metrics
# -------------------------------
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Score", f"{score:.4f}")

with col2:
    st.metric("Alert Level", alert_level)

with col3:
    st.metric("Alert Type", alert_type)

with col4:
    st.metric("Security Level", security_level)

# -------------------------------
# System status
# -------------------------------
st.subheader("System Status")

if security_level == "SAFE":
    st.success("System is operating normally.")
elif security_level == "SUSPICIOUS":
    st.warning("Suspicious activity detected. Please review logs.")
else:
    st.error("Critical threat detected. Immediate action required.")

# -------------------------------
# Reason section
# -------------------------------
st.subheader("Reason for Alert")
st.write("Multiple invalid login attempts and connection closure patterns detected.")

# -------------------------------
# Sample logs
# -------------------------------
st.subheader("Sample Logs")
st.code(
    """2026-04-05 Invalid user wronguser from 127.0.0.1
Connection closed by invalid user
Failed password for invalid user admin from 192.168.1.10""",
    language="text",
)

# -------------------------------
# Alerts section
# -------------------------------
st.subheader("Alerts")
st.error("⚠ Authentication attack detected")
st.error("⚠ Multiple invalid login attempts")

# -------------------------------
# Extra note
# -------------------------------
st.info(
    "Security level is determined from the anomaly score so that users can quickly understand the risk level."
)