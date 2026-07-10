# Network Security AI Agent

A small security tool that watches network traffic, spots suspicious
activity, and can respond by sending alerts or blocking IP addresses.

It works on recorded traffic (pcap files) or on a live network interface.

## How it works

1. **Capture**: packets are grouped into flows (one conversation between
   two hosts).
2. **Detect**: each flow is scored by a machine learning model
   (Isolation Forest) trained on your own normal traffic. Port scans are
   also detected across many flows.
3. **Explain**: each detection gets a threat level (LOW, MEDIUM, HIGH,
   CRITICAL), a short explanation, and matching MITRE ATT&CK techniques.
4. **Respond**: HIGH and CRITICAL detections send alerts (Slack or
   webhooks). CRITICAL sources can be blocked with iptables if you turn
   that on.

The project has three parts:

| Part | What it is |
|---|---|
| `src/` | The agent: capture, detection, response |
| `src/api.py` | An HTTP API that runs next to the agent |
| `dashboard/` | A web dashboard (Next.js) for Vercel. Work in progress. |

## Quick start

You need Python 3.11 or newer on Linux.

```bash
pip install -r requirements.txt

# 1. Train the model on traffic you know is normal
python scripts/train_model.py --pcap normal-traffic.pcap --output models/model.joblib

# 2. Copy the settings file and point it at your model
cp .env.example .env        # then set SOC_MODEL_PATH=models/model.joblib

# 3. Start the API
python -m src.api            # http://127.0.0.1:8000/docs
```

Then upload a capture to `POST /api/analyze`, or use the agent from Python:

```python
from src import SOCAgent

soc = SOCAgent(model_path="models/model.joblib")
results = soc.analyze_pcap("suspicious.pcap")
print(results["threats_detected"])
```

## Settings

All settings are environment variables. `.env.example` lists every one
with an explanation. The most important:

| Variable | Default | Meaning |
|---|---|---|
| `SOC_DRY_RUN` | `true` | Only log what would happen. Set `false` to act. |
| `SOC_AUTO_BLOCK_CRITICAL` | `false` | Block sources of CRITICAL detections |
| `BLOCK_ALLOWLIST` | empty | IPs that must never be blocked (gateway, DNS, your own IP) |
| `SLACK_WEBHOOK_URL` | empty | Where to send alerts (must be https) |
| `SOC_MODEL_PATH` | empty | Trained model to load at startup |
| `SOC_API_KEY` | empty | Needed if the API accepts remote connections |

## Safety

- It starts in dry-run mode and never blocks anything until you allow it.
- Loopback, multicast and allowlisted IPs are never blocked.
- Blocking and live capture need root (or the `CAP_NET_RAW` and
  `CAP_NET_ADMIN` capabilities).
- The API only listens on 127.0.0.1 unless you set an API key.
- Put HTTPS in front of the API (for example Caddy or a Cloudflare Tunnel)
  before exposing it.

## Training data

Train on traffic from your own network when it is behaving normally. The
model learns what "normal" looks like, so the better that sample, the
fewer false alarms. Public datasets such as
[CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) are useful
for testing.

## Development

```bash
pip install -r requirements-dev.txt
```

The dashboard has its own instructions in `dashboard/README.md`.

## License

MIT. Created by [Muthoni Gathiithi](https://github.com/MuthoniGathiithi).
