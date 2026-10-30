# Project Name

Short description: a web-based forensic tool (FastAPI) that analyses disk images (.E01) using The Sleuth Kit.

## Setup (Windows)

1. Clone the repo
2. Create a venv: `python -m venv venv` then `venv\Scripts\activate`
3. Install deps: `pip install -r requirements.txt`
4. Download The Sleuth Kit (Windows binaries) from https://www.sleuthkit.org/sleuthkit/download.php and extract it into a `sleuthkit/` folder in the project root, so `sleuthkit/bin/fls.exe` exists
5. Create an empty `uploads/` folder

## Run

`uvicorn main:app --reload`

Then open http://127.0.0.1:8000
