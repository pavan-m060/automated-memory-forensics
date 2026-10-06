import subprocess
import sys
from pathlib import Path

import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_ROOT = PROJECT_ROOT / "output" / "gui_reports"


st.set_page_config(
    page_title="Automated Memory Forensics",
    page_icon="🛡️",
    layout="wide",
)


st.title("🛡️ Automated Memory Forensics Platform")
st.caption("Windows Memory Analysis • Rootkit • Process Injection • DLL • Hook • Correlation")


st.markdown("### Case Information")

col1, col2 = st.columns(2)

with col1:
    case_id = st.text_input("Case ID")
    examination_id = st.text_input("Examination ID")
    examiner_name = st.text_input("Examiner Name")

with col2:
    organization = st.text_input("Organization")
    evidence_id = st.text_input("Evidence ID")
    report_title = st.text_input(
        "Report Title",
        value="Automated Memory Forensics Examination Report",
    )

case_description = st.text_area(
    "Investigation / Case Description",
    height=100,
)

evidence_description = st.text_area(
    "Evidence Description",
    height=100,
)


st.markdown("### Memory Evidence")

memory_file = st.file_uploader(
    "Select Windows RAM memory image",
    type=["raw", "bin", "mem", "dmp"],
)


if memory_file is not None:
    st.success(
        f"Evidence selected: {memory_file.name} "
        f"({memory_file.size:,} bytes)"
    )


st.markdown("---")


if st.button("🔍 Analyze Memory Image", type="primary", use_container_width=True):

    required_fields = {
        "Case ID": case_id,
        "Examination ID": examination_id,
        "Examiner Name": examiner_name,
        "Organization": organization,
        "Evidence ID": evidence_id,
    }

    missing = [
        name for name, value in required_fields.items()
        if not value.strip()
    ]

    if missing:
        st.error(
            "Please provide: " + ", ".join(missing)
        )
        st.stop()

    if memory_file is None:
        st.error("Please select a memory image.")
        st.stop()

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    safe_case_id = "".join(
        character
        if character.isalnum() or character in "-_"
        else "_"
        for character in case_id
    )

    case_output = OUTPUT_ROOT / safe_case_id
    case_output.mkdir(parents=True, exist_ok=True)

    memory_path = case_output / memory_file.name

    with open(memory_path, "wb") as file:
        file.write(memory_file.getbuffer())

    command = [
        sys.executable,
        str(PROJECT_ROOT / "main.py"),
        "-f",
        str(memory_path),
        "-o",
        str(case_output),
        "--case-id",
        case_id,
        "--examination-id",
        examination_id,
        "--examiner-name",
        examiner_name,
        "--organization",
        organization,
        "--case-description",
        case_description,
        "--evidence-id",
        evidence_id,
        "--evidence-description",
        evidence_description,
        "--report-title",
        report_title,
    ]

    st.markdown("### Analysis Progress")

    progress = st.progress(0)
    status = st.empty()

    status.info("Starting forensic analysis...")
    progress.progress(10)

    try:
        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        progress.progress(100)

        if result.returncode != 0:
            st.error("Forensic analysis failed.")

            with st.expander("Technical output"):
                st.code(result.stdout + "\n" + result.stderr)

            st.stop()

        status.success("Forensic analysis completed successfully.")

        st.session_state["case_output"] = str(case_output)

        st.success("Reports generated successfully.")

    except Exception as error:
        st.error(f"Unable to start forensic analysis: {error}")


case_output = st.session_state.get("case_output")


if case_output:
    case_output_path = Path(case_output)

    pdf_path = case_output_path / "forensic_report.pdf"
    json_path = case_output_path / "forensic_report.json"
    html_path = case_output_path / "forensic_report.html"

    st.markdown("---")
    st.markdown("## 📊 Forensic Report")

    if pdf_path.exists():
        st.success("Professional forensic PDF is ready.")

        with open(pdf_path, "rb") as file:
            st.download_button(
                "📄 Download PDF Report",
                data=file.read(),
                file_name="forensic_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

    col1, col2 = st.columns(2)

    if json_path.exists():
        with open(json_path, "rb") as file:
            col1.download_button(
                "Download JSON Report",
                data=file.read(),
                file_name="forensic_report.json",
                mime="application/json",
                use_container_width=True,
            )

    if html_path.exists():
        with open(html_path, "rb") as file:
            col2.download_button(
                "Download HTML Report",
                data=file.read(),
                file_name="forensic_report.html",
                mime="text/html",
                use_container_width=True,
            )