import os
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
runs_dir = str(REPO_ROOT / "runs")
tasks_dir = str(REPO_ROOT / "tasks")
output_file = str(REPO_ROOT / "docs" / "gemini-2.0-flash-CVEs.md")

def get_gemini_runs():
    cve_data = {}
    if not os.path.exists(runs_dir): return cve_data
    
    for cve in os.listdir(runs_dir):
        cve_path = os.path.join(runs_dir, cve)
        if not os.path.isdir(cve_path): continue
        
        gemini_path = os.path.join(cve_path, "gemini-2.0-flash")
        if not os.path.isdir(gemini_path): continue
        
        cve_data[cve] = {"levels": {}, "special_reports": {}}
        
        for fname in ["investigation_report.md", "experiment_report.md", "proposal_approach.md", "justification_L2_vs_L3.md"]:
            fpath = os.path.join(gemini_path, fname)
            if not os.path.exists(fpath):
                fpath = os.path.join(cve_path, fname)
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    cve_data[cve]["special_reports"][fname] = f.read()
                    
        for root, dirs, files in os.walk(gemini_path):
            if "summary.json" in files:
                summary_path = os.path.join(root, "summary.json")
                with open(summary_path, "r", encoding="utf-8") as f:
                    try:
                        summary_data = json.load(f)
                    except:
                        summary_data = {}
                        
                level = summary_data.get("level", "Unknown")
                match = re.search(r'(L\d)', root, re.IGNORECASE)
                if match:
                    base_level = match.group(1).upper()
                    # Add seed folder name if nested to prevent overwriting keys
                    parent_dir = os.path.basename(os.path.dirname(root))
                    if parent_dir != "gemini-2.0-flash":
                        level = f"{base_level} ({parent_dir})"
                    else:
                        level = base_level
                
                iters = []
                for iter_folder in sorted(os.listdir(root)):
                    if iter_folder.startswith("iter_"):
                        iter_path = os.path.join(root, iter_folder)
                        iter_data = {"id": iter_folder}
                        
                        gen_path = os.path.join(iter_path, "generate.json")
                        if os.path.exists(gen_path):
                            with open(gen_path, "r", encoding="utf-8") as f:
                                try:
                                    gen_json = json.load(f)
                                    iter_data["rationale"] = gen_json.get("rationale", "")
                                except:
                                    pass
                        iters.append(iter_data)
                
                cve_data[cve]["levels"][level] = {
                    "folder": root,
                    "summary": summary_data,
                    "iterations": iters
                }
                
    return cve_data

def get_task_context(cve):
    context = ""
    target_task_dir = os.path.join(tasks_dir, cve)
    if not os.path.exists(target_task_dir): return context
    
    levels_dir = os.path.join(target_task_dir, "levels")
    if os.path.exists(levels_dir):
        l0_path = os.path.join(levels_dir, "L0_description.md")
        if os.path.exists(l0_path):
            with open(l0_path, "r", encoding="utf-8") as f:
                context = f.read()
    return context

def generate_markdown(cve_data):
    md = []
    md.append("# Comprehensive Gemini 2.0 Flash Fuzzing Experiment Analysis")
    md.append("\nThis document contains an exhaustive breakdown and analysis of multi-level LLM fuzzing experiments conducted with `gemini-2.0-flash` on various CVEs. Each CVE is broken down by context isolation levels (`L0` through `L3`) to demonstrate how the LLM's understanding and exploitation capability scales as more context is provided.")
    md.append("\n---")
    
    for cve, data in cve_data.items():
        md.append(f"\n## {cve}")
        
        context = get_task_context(cve)
        if context:
            desc_lines = context.split("\n")
            short_desc = ""
            for line in desc_lines:
                if line.strip() and not line.startswith("#"):
                    short_desc = line.strip()
                    break
            if short_desc:
                md.append(f"\n**Vulnerability Context:** {short_desc}\n")
        
        if data["special_reports"]:
            for fname, content in data["special_reports"].items():
                md.append(f"### {fname.replace('_', ' ').title()}")
                md.append(f"```markdown\n{content}\n```\n")
        
        md.append("### Level by Level Analysis")
        
        levels = sorted(data["levels"].keys(), reverse=True)
        if not levels:
            md.append("\n*No iteration data found for Gemini in this CVE.*")
            md.append("---\n")
            continue
            
        for level in levels:
            lvl_data = data["levels"][level]
            summary = lvl_data.get("summary", {})
            success = summary.get("success", False)
            total_iters = summary.get("total_iters", "Unknown")
            max_iters = summary.get("max_iters", "Unknown")
            status_icon = "✅ SUCCESS" if success else "❌ FAILURE"
            
            md.append(f"#### {level} Context - {status_icon}")
            md.append(f"- **Total Iterations Run:** {total_iters} (out of max {max_iters})")
            
            if success:
                md.append(f"- **Vulnerability Triggered At:** Iteration {summary.get('success_iter', total_iters)}")
            else:
                md.append("- **Outcome:** Failed to trigger crash within max iterations limit.")
            
            iters = lvl_data.get("iterations", [])
            if iters:
                md.append("\n**LLM Fuzzing Strategy per Iteration:**")
                md.append("*(Tracing the rationale applied by Gemini during generation)*\n")
                
                if len(iters) <= 5:
                    for it in iters:
                        rationale = it.get('rationale', 'No rationale provided.')
                        md.append(f"- **{it['id']}**: {rationale}")
                else:
                    md.append(f"- **{iters[0]['id']} (Initial Strategy)**: {iters[0].get('rationale', 'No rationale')}")
                    md.append(f"- **{iters[len(iters)//2]['id']} (Midpoint Strategy)**: {iters[len(iters)//2].get('rationale', 'No rationale')}")
                    if success:
                        md.append(f"- **{iters[-1]['id']} (Winning Strategy)**: {iters[-1].get('rationale', 'No rationale')}")
                    else:
                        md.append(f"- **{iters[-1]['id']} (Final Failed Strategy)**: {iters[-1].get('rationale', 'No rationale')}")
            md.append("\n")
            
        md.append("---\n")
        
    return "\n".join(md)

if __name__ == "__main__":
    cve_data = get_gemini_runs()
    md_content = generate_markdown(cve_data)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"Report saved to {output_file}")
