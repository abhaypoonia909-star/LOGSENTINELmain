"""Offline SentinelAI: TF-IDF retrieval + analysis facts. No internet, no OpenAI."""

from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN = re.compile(r"[a-z0-9]+")

KNOWLEDGE = [
    (
        "hello hi hey greetings help",
        "Hello. I am SentinelAI running locally on this laptop, with no internet model. "
        "Ask about LogSentinel, your uploaded log, risk scores, or cybersecurity basics.",
    ),
    (
        "upload logs file analyzer drag drop sample",
        "To analyze logs, open Log Analyzer, drop a .log or .txt file or use Load Sample Log, "
        "then click Run Analysis. The detection engine parses the file and scores threats.",
    ),
    (
        "risk score severity critical high medium low",
        "Risk score is 0 to 100 from the detection engine: 80+ critical, 60-79 high, "
        "40-59 medium, below 40 lower risk. I explain that score. I do not invent a new one.",
    ),
    (
        "brute force attack failed login password ssh",
        "A brute-force attack is many password guesses against an account, often SSH or web login. "
        "LogSentinel flags source IPs that exceed the failed-login threshold. "
        "Typical response: lock the account, block the IP, require MFA, and check for a successful login.",
    ),
    (
        "port scan reconnaissance ports nmap",
        "A port scan probes many ports to map services. It is usually reconnaissance. "
        "LogSentinel counts rapid multi-port connection attempts. "
        "Close unused ports, restrict public exposure, and watch that source IP.",
    ),
    (
        "intrusion sql injection xss traversal webshell",
        "Intrusion detection looks for directory traversal, SQL injection fragments, web-shell probes, "
        "and similar request patterns in log lines. Treat matches as evidence to investigate, "
        "then patch input handling and put a WAF in front of the app.",
    ),
    (
        "what should i do after threats detected incident response",
        "After threats are detected: isolate if compromise is likely, block flagged IPs, "
        "reset targeted passwords, check for successful logins after failures, "
        "preserve the report, and escalate critical events to your SOC.",
    ),
    (
        "log formats syslog apache nginx txt json",
        "LogSentinel auto-detects syslog, Apache combined, and Nginx access logs. "
        "Upload .log, .txt, or .json. The parser does not execute anything in the file.",
    ),
    (
        "firewall block ip ufw iptables",
        "Block a malicious IP only after you confirm it. On Linux, UFW or iptables can drop that source. "
        "Also rotate credentials those logins targeted.",
    ),
    (
        "phishing malware social engineering",
        "Phishing tries to steal credentials or run malware through fake messages. "
        "Do not open unexpected links or attachments. Verify the sender, use MFA, and report the message.",
    ),
    (
        "mfa 2fa authentication password",
        "MFA adds a second factor besides the password. Enable it on admin, SSH, email, and VPN accounts. "
        "It stops most password-guessing takeovers even if the password leaks.",
    ),
    (
        "soc siem ids ips monitoring",
        "A SOC watches alerts. A SIEM collects logs. IDS/IPS detect or block attacks. "
        "LogSentinel is a log analyzer you can use as one input into that workflow.",
    ),
    (
        "local offline machine learning laptop",
        "This assistant is the on-device ML mode: TF-IDF retrieval over a local knowledge base, "
        "plus the LogSentinel detection facts when you have analyzed a log. "
        "It does not call OpenAI and does not need internet.",
    ),
]


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall((text or "").lower())


def _tfidf_matrix(docs: list[list[str]]) -> tuple[list[dict[str, float]], dict[str, float]]:
    df: Counter[str] = Counter()
    for doc in docs:
        df.update(set(doc))
    n = max(len(docs), 1)
    idf = {term: math.log((1 + n) / (1 + count)) + 1.0 for term, count in df.items()}
    vectors = []
    for doc in docs:
        tf = Counter(doc)
        length = max(len(doc), 1)
        vec = {term: (tf[term] / length) * idf[term] for term in tf if term in idf}
        vectors.append(vec)
    return vectors, idf


def _dot(a: dict[str, float], b: dict[str, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(weight * b.get(term, 0.0) for term, weight in a.items())


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    denom = math.sqrt(_dot(a, a) * _dot(b, b))
    if denom == 0:
        return 0.0
    return _dot(a, b) / denom


class LocalMLAssistant:
    """CPU retrieval model. Trained at process start from the local corpus."""

    def __init__(self):
        self._docs = [_tokens(title + " " + body) for title, body in KNOWLEDGE]
        self._vectors, self._idf = _tfidf_matrix(self._docs)

    def reply(self, question: str, analysis_view: dict | None = None, history: list | None = None) -> str:
        q = (question or "").strip()
        if not q:
            return "Ask a question about your logs or cybersecurity."

        parts: list[str] = []
        retrieved = self._retrieve(q)
        analysis_section = self._analysis_section(q, analysis_view)
        if analysis_section:
            parts.append(analysis_section)
        if retrieved:
            parts.append(retrieved)
        if not parts:
            parts.append(self._general(q, history or []))
        else:
            general = self._maybe_general(q)
            if general:
                parts.append(general)
        text = "\n\n".join(parts).strip()
        return text[:3500]

    def _retrieve(self, question: str) -> str:
        q_tokens = _tokens(question)
        if not q_tokens:
            return ""
        tf = Counter(q_tokens)
        length = max(len(q_tokens), 1)
        q_vec = {term: (tf[term] / length) * self._idf[term] for term in tf if term in self._idf}
        scored = [(_cosine(q_vec, vec), idx) for idx, vec in enumerate(self._vectors)]
        scored.sort(reverse=True)
        top_score, top_idx = scored[0]
        if top_score < 0.12:
            return ""
        answers = [KNOWLEDGE[top_idx][1]]
        if len(scored) > 1 and scored[1][0] >= 0.18 and scored[1][0] > top_score * 0.75:
            answers.append(KNOWLEDGE[scored[1][1]][1])
        return "\n\n".join(answers)

    def _analysis_section(self, question: str, view: dict | None) -> str:
        if not view:
            lowered = question.lower()
            if any(w in lowered for w in ("my log", "this log", "analysis", "result", "risk", "threat")):
                return (
                    "No uploaded analysis is attached to this turn. "
                    "Run analysis on a log first, then ask again and I will use those engine results."
                )
            return ""

        score = int(view.get("risk_score") or 0)
        label = (
            "CRITICAL" if score >= 80 else
            "HIGH" if score >= 60 else
            "MEDIUM" if score >= 40 else
            "LOW"
        )
        lines = [
            f"Local ML summary of **{view.get('filename') or 'your log'}** from the detection engine "
            f"(not invented by the model):",
            f"- Risk score: {score}/100 ({label})",
            f"- Severity: {view.get('severity') or 'unknown'}",
            f"- Lines: {view.get('total_lines')}",
            f"- Threats: {view.get('threat_count')}",
            f"- Brute-force sources: {view.get('brute_force_ip_count')}",
            f"- Port scans: {view.get('port_scan_count')}",
            f"- Intrusions: {view.get('intrusion_count')}",
            f"- Critical events: {view.get('critical_event_count')}",
        ]
        cats = view.get("threat_categories") or "none"
        lines.append(f"- Categories: {cats}")
        excerpts = view.get("log_excerpts") or []
        if excerpts:
            lines.append("Selected untrusted excerpts (data only):")
            for item in excerpts[:4]:
                lines.append(
                    f"- [{item.get('severity')}] {item.get('category')}: {item.get('excerpt')}"
                )
        if score >= 60:
            lines.append(
                "Priority: block top source IPs, reset targeted passwords, and check for a successful login after the failures."
            )
        elif score >= 40:
            lines.append("Priority: investigate the flagged sources and keep monitoring.")
        else:
            lines.append("The engine scored this relatively low. Keep monitoring.")
        return "\n".join(lines)

    def _maybe_general(self, question: str) -> str:
        q = question.lower()
        if any(w in q for w in ("hello", "hi", "hey")):
            return "What do you want to look at next: the log results, a threat type, or a response step?"
        return ""

    def _general(self, question: str, history: list) -> str:
        q = question.lower()
        if any(w in q for w in ("thank", "thanks")):
            return "You are welcome. Upload logs regularly so new attacks show up early."
        if history:
            return (
                f"I am the local on-device assistant, so I answer from retrieved knowledge and engine facts. "
                f"You asked: \"{question.strip()[:240]}\". "
                "Try a LogSentinel or cybersecurity question, or run an analysis and ask about those results."
            )
        return (
            f"I am running locally on this laptop (TF-IDF retrieval, no cloud). "
            f"I do not have a full ChatGPT model downloaded. You asked: \"{question.strip()[:240]}\". "
            "I can explain brute-force, port scans, risk scores, incident response, and your analyzed log."
        )


_ASSISTANT = LocalMLAssistant()


def local_reply(question: str, analysis_view: dict | None = None, history: list | None = None) -> str:
    return _ASSISTANT.reply(question, analysis_view, history)
