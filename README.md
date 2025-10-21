# Symmetric-Key-Challenge-Response-Insight-Generator
Simulates symmetric key (one-way & two-way) authentication protocols using AES and nonce-based challenge–response. Generates datasets under normal and attack conditions for anomaly detection. Includes visualization and statistical analysis interface for protocol security evaluation.

## Web UI (Streamlit)

A simple Streamlit UI is provided at `ui/streamlit_app.py` to run the simulator, generate datasets, and view result files and logs.

Quick start:

1. Create and activate a virtual environment (recommended).
2. Install UI dependencies:

```powershell
python -m pip install -r ui/requirements_ui.txt
```

3. Run the Streamlit app:

```powershell
streamlit run ui/streamlit_app.py
```

The app provides three pages: Generate Dataset, Run Simulation, and Data & Logs. Use the Generate Dataset page to run `generate_dataset.py` with adjustable parameters.
