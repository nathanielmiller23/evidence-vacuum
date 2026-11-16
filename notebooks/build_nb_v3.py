"""Builds notebooks/v3_reviewer_colab.ipynb:  python notebooks/build_nb_v3.py"""
import json
from pathlib import Path

cells = []
md = lambda s: cells.append({"cell_type": "markdown", "metadata": {}, "source": s.strip("\n").splitlines(keepends=True)})
code = lambda s: cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
                               "source": s.strip("\n").splitlines(keepends=True)})

md(r'''
# Evidence Vacuum v3: reviewer evaluation (Colab T4)

Runs a reviewer (base model, optionally + an Adaption LoRA adapter) over a reviewer-input file and scores the **paired
control**: final action = reviewer action, but a proposed `close` becomes `collect_more` when the sensor-silence gate fires
(`gate_fires`, precomputed from telemetry only). Missing investigator answers (`prompt: null`) keep the investigator action.

**Setup:** Runtime → T4 GPU. Drive folder `MyDrive/evidence-vacuum-v3/` with the input file(s) and adapter archive(s).
Edit **only the CONFIG cell**, run all. Resumable. Re-run with a different CONFIG for each arm.
''')
code(r'''
!pip -q uninstall -y torchao
!pip -q install "transformers==5.23.0" "peft==0.21.3" "accelerate==1.15.0" "bitsandbytes==0.50.2"
''')
md("## CONFIG (edit this cell only)")
code(r'''
BASE = "Qwen/Qwen3.5-4B"          # the study used 4B (a 9B arm was planned but dropped)
ADAPTER_TAR = "adapter_v3.tar.gz"  # file in the Drive folder, or None for the untuned base model
NAME = "R4-v3"                     # arm name -> outputs/<NAME>__<inputs stem>.jsonl
INPUTS = "reviewer_dev_inputs.jsonl"
LOAD_4BIT = True                   # needed for 9B on a T4; 4B can use False
''')
code(r'''
import json, os, re, tarfile, time
import torch
from tqdm.auto import tqdm
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from google.colab import drive, userdata
drive.mount("/content/drive")
try:
    HF_TOKEN = userdata.get("HF_TOKEN")
except Exception:
    HF_TOKEN = None
assert torch.cuda.is_available(), "Runtime -> Change runtime type -> T4 GPU"
ROOT = "/content/drive/MyDrive/evidence-vacuum-v3"
OUT = f"{ROOT}/outputs"; os.makedirs(OUT, exist_ok=True)
recs = [json.loads(l) for l in open(f"{ROOT}/{INPUTS}") if l.strip()]
print(len(recs), "inputs |", torch.cuda.get_device_name(0))
tok = AutoTokenizer.from_pretrained(BASE, token=HF_TOKEN)
kw = dict(device_map="cuda", token=HF_TOKEN)
if LOAD_4BIT:
    kw["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16, bnb_4bit_quant_type="nf4")
else:
    kw["torch_dtype"] = torch.float16
model = AutoModelForCausalLM.from_pretrained(BASE, **kw).eval()
if ADAPTER_TAR:
    from peft import PeftModel
    adir = f"/content/adapter_{NAME}"
    if not os.path.exists(adir):
        os.makedirs(adir)
        with tarfile.open(f"{ROOT}/{ADAPTER_TAR}") as t: t.extractall(adir, filter="data")  # rejects absolute paths, ../ traversal, links out of the dir and device files
    found = [r for r, _, fs in os.walk(adir) if "adapter_config.json" in fs]; assert found, "no adapter_config.json"
    # Adaption checkpoints for multimodal bases may prefix keys with 'language_model'; prefer a text-only copy if present
    pick = sorted(found, key=lambda p: ("textonly" not in p, len(p)))[0]
    cfg = json.load(open(f"{pick}/adapter_config.json")); print("adapter:", pick, "base:", cfg.get("base_model_name_or_path"), "r=", cfg.get("r"))
    model = PeftModel.from_pretrained(model, pick).eval()
    lb = [(n, p) for n, p in model.named_parameters() if "lora_B" in n]
    nz = sum(1 for _, p in lb if p.detach().abs().sum().item() > 0)
    print(f"LoRA-B tensors attached: {len(lb)}, non-zero: {nz}")
    assert len(lb) > 0 and nz > 0, "adapter did not attach (try the other archive copy)"
''')
code(r'''
STATUS = {"malicious_supported": "escalate", "benign_supported": "close", "insufficient_evidence": "collect_more"}
def parse(text):
    m = re.search(r"\{.*\}", text or "", flags=re.S)
    if not m: return None
    try: d = json.loads(m.group(0))
    except json.JSONDecodeError: return None
    if d.get("epistemic_status") not in STATUS or d.get("recommended_action") not in ("close", "escalate", "collect_more"): return None
    return d

@torch.inference_mode()
def review(prompt):
    enc = tok.apply_chat_template([{"role": "user", "content": prompt}], add_generation_prompt=True,
                                  return_tensors="pt", return_dict=True, enable_thinking=False)
    ids, mask = enc["input_ids"].to(model.device), enc["attention_mask"].to(model.device)
    out = model.generate(ids, attention_mask=mask, max_new_tokens=320, do_sample=False, temperature=None, top_p=None,
                         pad_token_id=tok.eos_token_id)
    text = tok.decode(out[0, ids.shape[1]:], skip_special_tokens=True)
    return text, parse(text), int(ids.shape[1])

path = f"{OUT}/{NAME}__{INPUTS.replace('.jsonl', '')}.jsonl"
done = {json.loads(l)["run_id"] for l in open(path)} if os.path.exists(path) else set()
t, d, n = review(next(r for r in recs if r["prompt"])["prompt"]); print("smoke:", n, "tokens |", t[:200], "| parsed:", d)
with open(path, "a") as f:
    for r in tqdm([r for r in recs if r["run_id"] not in done and r["prompt"]], desc=NAME):
        t0 = time.time(); text, d, n = review(r["prompt"])
        f.write(json.dumps({"run_id": r["run_id"], "reviewer": NAME, "raw": text, "parsed": d, "n_in": n,
                            "secs": round(time.time() - t0, 2)}) + "\n"); f.flush()
print("saved", path)
''')
md("## Score: investigator alone vs reviewer vs reviewer + silence gate")
code(r'''
WANT = {"MALICIOUS_SUPPORTED": {"escalate"}, "BENIGN_SUPPORTED": {"close"}, "INSUFFICIENT": {"escalate", "collect_more"}}
outs = {json.loads(l)["run_id"]: json.loads(l) for l in open(path)}
def score(fn, title):
    c = j = u = 0; nb = sum(r["label"] == "BENIGN_SUPPORTED" for r in recs)
    for r in recs:
        a = fn(r)
        c += a in WANT[r["label"]]; j += a == "close" and r["label"] == "BENIGN_SUPPORTED"; u += a == "close" and r["label"] != "BENIGN_SUPPORTED"
    print(f"{title:28} correct {c}/{len(recs)} | justified closes {j}/{nb} | unsupported closes {u}")
rev = lambda r: ((outs.get(r["run_id"]) or {}).get("parsed") or {}).get("recommended_action", r["investigator_action"])
gate = lambda a, r: "collect_more" if a == "close" and r["gate_fires"] else a
score(lambda r: r["investigator_action"], "investigator alone")
score(lambda r: gate(r["investigator_action"], r), "investigator + gate")
score(rev, f"{NAME}")
score(lambda r: gate(rev(r), r), f"{NAME} + gate")
print("invalid reviewer outputs:", sum(1 for r in recs if r["prompt"] and not (outs.get(r["run_id"]) or {}).get("parsed")))
''')
nb = {"cells": cells, "metadata": {"accelerator": "GPU", "colab": {"gpuType": "T4"},
                                   "kernelspec": {"display_name": "Python 3", "name": "python3"}, "language_info": {"name": "python"}},
      "nbformat": 4, "nbformat_minor": 0}
p = Path(__file__).resolve().parent / "v3_reviewer_colab.ipynb"
p.write_text(json.dumps(nb, indent=1, ensure_ascii=False), encoding="utf-8")
print("wrote", p)
