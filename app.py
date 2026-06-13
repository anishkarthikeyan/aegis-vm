"""Streamlit UI for scanning pasted Python with aegis_vm."""

from __future__ import annotations

import streamlit as st

from aegis_vm import scan_code
from aegis_vm.policy import SafetyPolicy

EXAMPLE_SNIPPETS = {
    "Safe: arithmetic": "total = sum([1, 2, 3, 4])\nprint(total)",
    "Blocked: eval": "result = eval('2 + 2')",
    "Blocked: os.system": "import os\nos.system('echo pwned')",
    "Blocked: network": (
        "import requests\nrequests.get('https://example.com')"
    ),
}

POLICY_OPTIONS = {
    "Strict (block all imports)": SafetyPolicy.strict(),
    "Lenient (allow benign imports)": SafetyPolicy.lenient(),
}


def _line_status(source: str, flagged_nodes: list[dict[str, object]]) -> list[dict[str, object]]:
    lines = source.splitlines()
    flagged_by_line: dict[int, list[dict[str, object]]] = {}
    for node in flagged_nodes:
        lineno = int(node["lineno"])
        flagged_by_line.setdefault(lineno, []).append(node)

    rows: list[dict[str, object]] = []
    for index, line in enumerate(lines, start=1):
        hits = flagged_by_line.get(index, [])
        rows.append(
            {
                "line": index,
                "status": "blocked" if hits else "allowed",
                "rules": ", ".join(sorted({str(node["rule_id"]) for node in hits})),
                "code": line,
            }
        )
    return rows


def main() -> None:
    st.set_page_config(
        page_title="Aegis-VM Scanner",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("Aegis-VM Code Scanner")
    st.caption("Paste Python source code to inspect it with AST-based safety rules.")

    with st.sidebar:
        st.header("Scan settings")
        policy_label = st.selectbox("Policy", list(POLICY_OPTIONS.keys()))
        policy = POLICY_OPTIONS[policy_label]

        st.header("Examples")
        for label, snippet in EXAMPLE_SNIPPETS.items():
            if st.button(label, use_container_width=True):
                st.session_state["source_code"] = snippet

    source = st.text_area(
        "Python code",
        height=320,
        placeholder="Paste Python code here...",
        key="source_code",
    )

    scan_clicked = st.button("Scan code", type="primary", use_container_width=False)
    if not source.strip():
        st.info("Paste code above, then click **Scan code**.")
        return

    if scan_clicked:
        st.session_state["report"] = scan_code(source, policy=policy)
        st.session_state["scanned_source"] = source

    if "report" not in st.session_state:
        st.info("Click **Scan code** to run the safety inspection.")
        return

    if st.session_state.get("scanned_source") != source:
        st.warning("Code changed since the last scan. Click **Scan code** to refresh results.")

    report = st.session_state["report"]

    severity = str(report["severity"])
    reasons = list(report["reasons"])
    flagged_nodes = list(report["flagged_nodes"])

    verdict_col, metric_col, rules_col = st.columns([2, 1, 1])
    with verdict_col:
        if severity == "safe":
            st.success("ALLOWED — no safety violations detected.")
        else:
            st.error("BLOCKED — one or more safety violations detected.")

    with metric_col:
        blocked_lines = {
            int(node["lineno"])
            for node in flagged_nodes
        }
        st.metric("Flagged lines", len(blocked_lines))
    with rules_col:
        st.metric("Violations", len(flagged_nodes))

    if reasons and not flagged_nodes:
        st.warning(reasons[0])

    detail_tab, lines_tab = st.tabs(["Violations", "Line breakdown"])

    with detail_tab:
        if flagged_nodes:
            st.subheader("Blocked constructs")
            st.dataframe(
                flagged_nodes,
                use_container_width=True,
                hide_index=True,
            )
            st.subheader("Reasons")
            for reason in reasons:
                st.markdown(f"- {reason}")
        elif severity == "safe":
            st.markdown("This snippet passed all active safety checks.")

    with lines_tab:
        rows = _line_status(source, flagged_nodes)
        if not rows:
            st.markdown("No lines to display.")
        else:
            allowed_count = sum(1 for row in rows if row["status"] == "allowed")
            blocked_count = len(rows) - allowed_count
            left, right = st.columns(2)
            left.metric("Allowed lines", allowed_count)
            right.metric("Blocked lines", blocked_count)

            for row in rows:
                prefix = "🚫 Blocked" if row["status"] == "blocked" else "✅ Allowed"
                rules = f" — {row['rules']}" if row["rules"] else ""
                st.markdown(f"**{prefix}** · line {row['line']}{rules}")
                st.code(str(row["code"]), language="python")


if __name__ == "__main__":
    main()
