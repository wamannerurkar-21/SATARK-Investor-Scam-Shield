# SATARK Integration Notes

Merged components:
- Member 1: `artifacts/satark/ai`, `artifacts/satark/detection`, `artifacts/satark/data`
- Member 2: `artifacts/satark/ocr`, `artifacts/satark/verification`
- Member 3: Streamlit UI, `satark_core.py`, database, translations, app entry point

Run:
`streamlit run app.py`

Install:
`pip install -r requirements.txt`

Tests:
`python -m unittest discover -s tests -v`

Optional services are still disabled unless the UI opt-in is enabled. Never commit `.env` or secrets.
