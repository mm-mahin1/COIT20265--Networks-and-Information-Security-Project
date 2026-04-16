
set -e

echo "=============================================="
echo "  COIT20265 NLP Anomaly Detection — EC2 Setup"
echo "=============================================="

# ── 1. System update ──────────────────────────────────
echo ""
echo "[1/7] Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y

# ── 2. Python & pip ───────────────────────────────────
echo ""
echo "[2/7] Installing Python 3.11 and pip..."
sudo apt-get install -y python3.11 python3-pip python3.11-venv

# ── 3. Create virtual environment ─────────────────────
echo ""
echo "[3/7] Creating virtual environment..."
python3.11 -m venv ~/nlp-anomaly-env
source ~/nlp-anomaly-env/bin/activate

# ── 4. Install Python dependencies ────────────────────
echo ""
echo "[4/7] Installing Python packages..."
pip install --upgrade pip
pip install \
    streamlit==1.35.0 \
    pandas==2.2.2 \
    numpy==1.26.4 \
    scikit-learn==1.5.0 \
    matplotlib==3.9.0 \
    plotly==5.22.0 \
    boto3==1.34.131 \
    joblib==1.4.2 \
    transformers==4.41.0 \
    torch==2.3.0 \
    sentence-transformers==3.0.1

echo "All packages installed."

# ── 5. Create project directory ───────────────────────
echo ""
echo "[5/7] Setting up project directory..."
mkdir -p ~/nlp-anomaly-detection/threat_logs
cd ~/nlp-anomaly-detection

cp ~/uploads/dashboard.py           . 2>/dev/null || echo "  (dashboard.py not yet uploaded)"
cp ~/uploads/generate_threat_logs.py . 2>/dev/null || echo "  (generate_threat_logs.py not yet uploaded)"
cp ~/uploads/full_dataset_final.csv . 2>/dev/null || echo "  (full_dataset_final.csv not yet uploaded)"

# ── 6. Generate threat test logs ──────────────────────
echo ""
echo "[6/7] Generating test threat logs..."
if [ -f "generate_threat_logs.py" ]; then
    python3 generate_threat_logs.py
    echo "  Threat logs created in ./threat_logs/"
else
    echo "  generate_threat_logs.py not found — skipping."
fi

# ── 7. Configure Security Group reminder ──────────────
echo ""
echo "[7/7] Security Group reminder..."
echo "  ┌─────────────────────────────────────────────────┐"
echo "  │  Make sure your EC2 Security Group allows:      │"
echo "  │  Inbound TCP port 8501  (Streamlit dashboard)   │"
echo "  │  Inbound TCP port 22    (SSH — already done)    │"
echo "  └─────────────────────────────────────────────────┘"
echo ""
echo "  To add port 8501 in AWS Console:"
echo "  EC2 → Instances → cybersecurity-log-server"
echo "  → Security → Security Groups → Edit Inbound Rules"
echo "  → Add Rule: Custom TCP | Port 8501 | Source 0.0.0.0/0"

# ── Start dashboard ───────────────────────────────────
echo ""
echo "=============================================="
echo "  Starting Streamlit Dashboard..."
echo "  Access at: http://18.232.185.142:8501"
echo "=============================================="
echo ""
echo "  Press Ctrl+C to stop."
echo ""

cd ~/nlp-anomaly-detection
source ~/nlp-anomaly-env/bin/activate

# Run with nohup so it stays up after SSH disconnect
nohup streamlit run dashboard.py \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --browser.gatherUsageStats false \
    > ~/dashboard.log 2>&1 &

DASHBOARD_PID=$!
echo "Dashboard started with PID $DASHBOARD_PID"
echo "Log file: ~/dashboard.log"
echo ""
echo "To stop the dashboard later:"
echo "  kill $DASHBOARD_PID"
echo ""
echo "To view logs:"
echo "  tail -f ~/dashboard.log"
