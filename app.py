import streamlit as st
import requests

st.set_page_config(page_title="Cyber Threat Detection", layout="wide")

st.title("🛡️ AI-Powered Cyber Threat Detection Dashboard")

st.sidebar.header("🔧 Input Log Features")

login_attempts = st.sidebar.slider("Login Attempts", 0, 10, 1)
hour = st.sidebar.slider("Access Time (Hour)", 0, 23, 12)
session = st.sidebar.slider("Session Duration Level", 0, 10, 3)
ip = st.sidebar.number_input("IP Address (numeric)", value=123456789)

file_access = st.sidebar.selectbox("File Access", [0, 1])
file_delete = st.sidebar.selectbox("File Deletion", [0, 1])
network = st.sidebar.slider("Network Activity", 0, 10, 2)
process = st.sidebar.slider("Process Activity", 0, 10, 2)
suspicious_cmd = st.sidebar.selectbox("Suspicious Command", [0, 1])
remote = st.sidebar.selectbox("Remote Login", [0, 1])
usb = st.sidebar.selectbox("USB Activity", [0, 1])

if st.button("🔍 Analyze Log"):

    user_input = [
        login_attempts,
        hour,
        session,
        ip,
        file_access,
        file_delete,
        network,
        process,
        suspicious_cmd,
        remote,
        usb
    ]

    try:
        response = requests.post(
            "http://127.0.0.1:5000/analyze",
            json={"log": user_input}
        )

        data = response.json()

        st.subheader("📊 Result")
        st.metric("AI Risk Score", data["score"])

        if "ATTACK" in data["verdict"]:
            st.error(data["verdict"])
        elif "SUSPICIOUS" in data["verdict"]:
            st.warning(data["verdict"])
        else:
            st.success(data["verdict"])

        st.info(data["note"])

    except:
        st.error("⚠️ Cannot connect to backend. Make sure Flask is running.")