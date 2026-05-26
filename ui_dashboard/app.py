import streamlit as st
import subprocess

st.title("Solana AI Security Pipeline")

if st.button("Run Scan"):
    st.write("🔄 Running pipeline... please wait")

    result = subprocess.run(
        ["python", "main.py"],
        capture_output=True,
        text=True
    )

    st.subheader("STDOUT")
    st.text(result.stdout)

    st.subheader("STDERR")
    st.text(result.stderr)

    st.success("Scan completed")