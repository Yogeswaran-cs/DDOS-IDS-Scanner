import os
import io
import joblib
import pandas as pd
import numpy as np
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from scapy.all import rdpcap, IP, TCP
from sklearn.ensemble import IsolationForest

app = FastAPI()

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- FEATURES ----------------
FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Flow IAT Mean",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd PSH Flags",
    "FIN Flag Count",
]

# ---------------- COLUMN ALIASES ----------------
COLUMN_ALIASES = {
    "flowduration": "Flow Duration",
    "totfwdpkts": "Total Fwd Packets",
    "totbwdpkts": "Total Backward Packets",
    "totlenfwdpkts": "Total Length of Fwd Packets",
    "fwdpktlenmax": "Fwd Packet Length Max",
    "flowiatmean": "Flow IAT Mean",
    "fwdiattot": "Fwd IAT Total",
    "fwdiatmean": "Fwd IAT Mean",
    "fwdpshflags": "Fwd PSH Flags",
    "finflagcnt": "FIN Flag Count",
}

# ---------------- MODEL ----------------
MODEL_PATH = "iso_forest_model.pkl"

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
    print("✅ Model loaded")
else:
    print("⚠️ Model not found, training dummy model")
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(np.random.rand(200, len(FEATURES)))

@app.get("/")
def root():
    return {"status": "online"}

# ---------------- PCAP PROCESSING ----------------
def process_pcap(file_bytes: bytes) -> pd.DataFrame:
    packets = rdpcap(io.BytesIO(file_bytes))
    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        key = (pkt[IP].src, pkt[IP].dst)
        if key not in flows:
            flows[key] = {
                "start": pkt.time,
                "end": pkt.time,
                "fwd": 0,
                "bwd": 0,
                "flen": 0,
                "fmax": 0,
                "psh": 0,
                "fin": 0,
            }

        f = flows[key]
        f["end"] = pkt.time
        f["fwd"] += 1
        f["flen"] += len(pkt)
        f["fmax"] = max(f["fmax"], len(pkt))

        if TCP in pkt:
            if "P" in str(pkt[TCP].flags):
                f["psh"] += 1
            if "F" in str(pkt[TCP].flags):
                f["fin"] += 1

    rows = []
    for v in flows.values():
        dur = float(v["end"] - v["start"])
        rows.append([
            dur,
            v["fwd"],
            v["bwd"],
            v["flen"],
            v["fmax"],
            dur / v["fwd"] if v["fwd"] else 0,
            dur,
            dur / v["fwd"] if v["fwd"] else 0,
            v["psh"],
            v["fin"],
        ])

    return pd.DataFrame(rows, columns=FEATURES)

# ---------------- ANALYZE ENDPOINT ----------------
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()

    # -------- PCAP --------
    if file.filename.lower().endswith((".pcap", ".pcapng")):
        df = process_pcap(content)

    # -------- CSV --------
    else:
        try:
            df_raw = pd.read_csv(io.BytesIO(content), sep=None, engine="python")
        except Exception:
            raise HTTPException(400, "Unable to read CSV")

        # Clean headers
        df_raw.columns = (
            df_raw.columns.str.strip()
            .str.lower()
            .str.replace(" ", "")
            .str.replace("_", "")
            .str.replace("-", "")
        )
 
        # Rename columns
        rename_map = {c: COLUMN_ALIASES[c] for c in df_raw.columns if c in COLUMN_ALIASES}
        df_raw = df_raw.rename(columns=rename_map)

        # -------- SAFE FEATURE HANDLING --------
        df = pd.DataFrame()
        for feature in FEATURES:
            if feature in df_raw.columns:
                df[feature] = pd.to_numeric(df_raw[feature], errors="coerce").fillna(0)
            else:
                df[feature] = 0.0

    if df.empty:
        raise HTTPException(400, "No usable data found")

    # -------- ML INFERENCE --------
    scores = model.decision_function(df)

    data = []
    for i, s in enumerate(scores):
        data.append({
            "id": i,
            "raw_score": float(s),
            "label": "Anomaly" if s < -0.05 else "Normal",
            "features": df.iloc[i].to_dict(),
        })

    safety = int(np.clip(((np.mean(scores) + 0.15) / 0.3) * 100, 0, 100))

    return {
        "summary": {
            "avg_safety": safety,
            "total_flows": len(data),
            "anomalies": len([d for d in data if d["label"] == "Anomaly"]),
        },
        "data": data,
    }

# ---------------- RUN ----------------
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)