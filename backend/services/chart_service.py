import io, base64
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

class ChartService:
    def generate_all(self, analysis: dict) -> dict[str, str]:
        stats = analysis.get("stats", {})
        charts = {}
        charts["level_pie"] = self._pie(stats.get("level_dist", {}), "Log Levels")
        charts["hourly_bar"] = self._bar(stats.get("hourly_dist", {}), "Hourly Activity")
        charts["top_ips_bar"] = self._bar(stats.get("top_ips", {}), "Top IPs")
        charts["status_bar"] = self._bar(stats.get("status_dist", {}), "HTTP Status")
        charts["threat_summary_bar"] = self._bar({
            "Brute Force": len(analysis.get("brute_force", {}).get("flagged_ips", [])),
            "Port Scan": analysis.get("port_scan", {}).get("event_count", 0),
            "Intrusion": analysis.get("intrusion", {}).get("event_count", 0),
            "Critical": analysis.get("critical_events", {}).get("event_count", 0),
        }, "Threat Summary")
        return {k: v for k, v in charts.items() if v}

    def _fig_to_b64(self, fig) -> str:
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight", facecolor="#0f1428")
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode()

    def _pie(self, data: dict, title: str) -> str | None:
        if not data: return None
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.pie(data.values(), labels=data.keys(), autopct="%1.0f%%")
        ax.set_title(title, color="white")
        fig.patch.set_facecolor("#0f1428"); ax.set_facecolor("#0f1428")
        return self._fig_to_b64(fig)

    def _bar(self, data: dict, title: str) -> str | None:
        if not data: return None
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.bar(list(map(str, data.keys())), list(data.values()), color="#00d4ff")
        ax.set_title(title, color="white")
        fig.patch.set_facecolor("#0f1428"); ax.set_facecolor("#0f1428")
        ax.tick_params(colors="white")
        return self._fig_to_b64(fig)