# Aegis CVE Enrichment UI

The interface uploads a CSV, shows one unchanged source row per unique CVE,
and lets the user select a contiguous range for enrichment. When a compatible
enrichment CSV already exists in `../data`, **Run pipeline** offers to reuse the
newest saved file or run a fresh enrichment. Both paths generate and display
`data/grouped_by_comp.csv` on a component-selection page. Only checked
product/component groups are written to the selected-run input and sent to the
remediation pipeline.

## Run the development UI

Start the Flask API from `aegis_engine_prod`:

```powershell
pip install -r .\requirements.txt
python .\app.py
```

In another terminal, start React from `aegis_engine_prod\ui`:

```powershell
npm.cmd install
npm.cmd run dev
```

Open `http://127.0.0.1:5173`.

## Run as one application

Build React once from `aegis_engine_prod\ui`:

```powershell
npm.cmd install
npm.cmd run build
```

Then start the Flask API from `aegis_engine_prod`:

```powershell
python .\app.py
```

Open `http://127.0.0.1:5000`.
