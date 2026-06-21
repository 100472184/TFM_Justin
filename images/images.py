from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

# Output folder requested for the LaTeX figures.
OUT_DIR = Path(__file__).resolve().parent
OUT_DIR.mkdir(parents=True, exist_ok=True)

# -----------------------------
# Data from the TFM campaign
# -----------------------------

cve_data = [
    ("CVE-2014-2525\nlibyaml", 24, 16, 8, 66.7, 37.7),
    ("CVE-2016-9827\nlibming", 24, 15, 9, 62.5, 44.3),
    ("CVE-2021-32292\njsonc", 24, 21, 3, 87.5, 27.1),
    ("CVE-2022-24724\ncmark-gfm", 24, 16, 8, 66.7, 41.8),
    ("CVE-2022-4899\nzstd", 24, 15, 9, 62.5, 45.1),
    ("CVE-2023-29469\nlibxml2", 24, 5, 19, 20.8, 80.6),
    ("CVE-2023-39804\ngnutar", 24, 18, 6, 75.0, 34.3),
    ("CVE-2024-25062\nlibxml2", 24, 0, 24, 0.0, 100.0),
    ("CVE-2024-4323\nfluentbit", 48, 48, 0, 100.0, 10.4),
    ("CVE-2024-57970\nlibarchive", 24, 21, 3, 87.5, 22.0),
    ("CVE-2025-26623\nexiv2", 24, 1, 23, 4.2, 96.1),
    ("CVE-2025-49014\njq", 24, 12, 12, 50.0, 61.7),
]

model_data = [
    ("Gemini", 52, 39, 13, 75.0, 13.48),
    ("DeepSeek", 52, 39, 13, 75.0, 13.61),
    ("GLM", 52, 35, 17, 67.3, 18.25),
    ("GPT-OSS", 52, 27, 25, 51.9, 22.23),
    ("Qwen", 52, 26, 26, 50.0, 22.73),
    ("Ministral", 52, 22, 30, 42.3, 25.23),
]

level_success = {
    "DeepSeek":  [69.2, 69.2, 76.9, 84.6],
    "Gemini":   [61.5, 76.9, 76.9, 84.6],
    "GLM":      [38.5, 69.2, 69.2, 92.3],
    "GPT-OSS":  [30.8, 23.1, 76.9, 76.9],
    "Ministral":[30.8, 23.1, 46.2, 69.2],
    "Qwen":     [23.1, 46.2, 46.2, 84.6],
}

# -----------------------------
# General plot helper
# -----------------------------

def save_current_figure(filename: str) -> None:
    path = OUT_DIR / filename
    plt.tight_layout()
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

# -----------------------------
# Fig. 2: Success rate by CVE
# LaTeX reference:
# \includegraphics[width=0.95\textwidth]{cve_success_rate.png}
# -----------------------------

cve_labels = [row[0] for row in cve_data]
cve_rates = [row[4] for row in cve_data]

order = np.argsort(cve_rates)
sorted_labels = [cve_labels[i] for i in order]
sorted_rates = [cve_rates[i] for i in order]

plt.figure(figsize=(10.5, 5.2))
bars = plt.bar(range(len(sorted_rates)), sorted_rates)
plt.xticks(range(len(sorted_labels)), sorted_labels, rotation=45, ha="right", fontsize=8)
plt.ylabel("Success rate (%)")
plt.xlabel("CVE task")
plt.title("Success Rate by CVE")
plt.ylim(0, 110)
plt.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.7)

for bar, value in zip(bars, sorted_rates):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 2,
        f"{value:.1f}%",
        ha="center",
        va="bottom",
        fontsize=7,
    )

save_current_figure("cve_success_rate.png")

# -----------------------------
# Fig. 3: Global success rate by model
# LaTeX reference:
# \includegraphics[width=\columnwidth]{model_success_rate.png}
# -----------------------------

model_labels = [row[0] for row in model_data]
model_rates = [row[4] for row in model_data]
model_iters = [row[5] for row in model_data]

plt.figure(figsize=(5.2, 3.6))
bars = plt.bar(model_labels, model_rates)
plt.ylabel("Success rate (%)")
plt.xlabel("Model")
plt.title("Global Success Rate by Model")
plt.ylim(0, 100)
plt.xticks(rotation=30, ha="right")
plt.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.7)

for bar, value, iters in zip(bars, model_rates, model_iters):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 2,
        f"{value:.1f}%\n{iters:.1f} it.",
        ha="center",
        va="bottom",
        fontsize=7,
    )

save_current_figure("model_success_rate.png")

# -----------------------------
# Fig. 4: Model x information-level heatmap
# LaTeX reference:
# \includegraphics[width=\columnwidth]{model_level_heatmap.png}
# -----------------------------

heatmap_models = list(level_success.keys())
levels = ["L0", "L1", "L2", "L3"]
matrix = np.array([level_success[m] for m in heatmap_models])

plt.figure(figsize=(5.2, 3.7))
im = plt.imshow(matrix, aspect="auto", vmin=0, vmax=100)
plt.colorbar(im, label="Success rate (%)")
plt.xticks(range(len(levels)), levels)
plt.yticks(range(len(heatmap_models)), heatmap_models)
plt.xlabel("Information level")
plt.ylabel("Model")
plt.title("Success Rate by Model and Information Level")

for i in range(matrix.shape[0]):
    for j in range(matrix.shape[1]):
        plt.text(
            j,
            i,
            f"{matrix[i, j]:.1f}",
            ha="center",
            va="center",
            fontsize=8,
        )

save_current_figure("model_level_heatmap.png")

# -----------------------------
# Fig. 5: Budget vs success by CVE
# LaTeX reference:
# \includegraphics[width=\columnwidth]{cve_budget_success_scatter.png}
# -----------------------------

scatter_labels = [row[0].replace("\n", "_") for row in cve_data]
scatter_rates = [row[4] for row in cve_data]
scatter_budgets = [row[5] for row in cve_data]
scatter_runs = [row[1] for row in cve_data]

# Marker size is proportional to the number of runs.
sizes = [40 + runs * 2.5 for runs in scatter_runs]

plt.figure(figsize=(5.4, 4.1))
plt.scatter(scatter_budgets, scatter_rates, s=sizes, alpha=0.75)
plt.xlabel("Average budget consumed (%)")
plt.ylabel("Success rate (%)")
plt.title("Budget Consumption vs Success Rate by CVE")
plt.xlim(-5, 105)
plt.ylim(-5, 105)
plt.grid(True, linestyle="--", linewidth=0.5, alpha=0.7)

for label, x, y in zip(scatter_labels, scatter_budgets, scatter_rates):
    short_label = label.replace("CVE-", "").replace("_", "\n")
    plt.annotate(
        short_label,
        (x, y),
        textcoords="offset points",
        xytext=(4, 4),
        fontsize=6,
    )

save_current_figure("cve_budget_success_scatter.png")

print("\nAll figures generated successfully.")
print(f"Use this in LaTeX: \\graphicspath{{{{images/}}{{./}}}}")
