from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
import os
import subprocess
import shutil
import pandas as pd
import time
import re
from datetime import datetime
from pathlib import Path

app = FastAPI()

# --- Configuration ---
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
RECOVERED_DIR = BASE_DIR / "recovered"
STATIC_DIR = BASE_DIR / "static"
BIN_DIR = BASE_DIR / "sleuthkit" / "bin"

# Tools
TSK_RECOVER = BIN_DIR / "tsk_recover.exe"
TSK_FLS = BIN_DIR / "fls.exe"
TSK_ISTAT = BIN_DIR / "istat.exe"

UPLOAD_DIR.mkdir(exist_ok=True)
RECOVERED_DIR.mkdir(exist_ok=True)

# Status tracking
jobs = {}

# --- Helper Functions ---
def normalize_time(timestr):
    timestr = timestr.strip()
    if "(" in timestr:
        timestr = timestr.split("(")[0].strip()
    try:
        return datetime.strptime(timestr, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

def parse_istat(image_path, inode):
    try:
        cmd = [str(TSK_ISTAT), str(image_path), str(inode)]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(errors="ignore")
        
        events = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Written:"):
                ts = normalize_time(line.replace("Written:", ""))
                if ts: events.append(("File modified", ts))
            elif line.startswith("Accessed:"):
                ts = normalize_time(line.replace("Accessed:", ""))
                if ts: events.append(("File accessed", ts))
            elif line.startswith("Created:"):
                ts = normalize_time(line.replace("Created:", ""))
                if ts: events.append(("File created", ts))
        return events
    except:
        return []

def get_all_inodes(image_path):
    file_list = []
    try:
        # -r: recursive, -p: full path, -d: deleted only (for recovered), -u: undeleted (for existing)
        # We run it once to get everything and parse the status
        cmd = [str(TSK_FLS), "-r", "-p", str(image_path)]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(errors="ignore")
        
        # Regex to capture: Type (r/d/-), Inode (12345), Filename
        # fls output example: "r/r * 12345: path/to/file.txt" (* indicates deleted)
        pattern = re.compile(r"(\w/\w)\s+(\*?)\s*(\d+):\s+(.+)")
        
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ftype, deleted_flag, inode, fname = match.groups()
                if "r/r" in ftype: # Regular files only
                    is_deleted = deleted_flag.strip() == "*"
                    file_list.append({
                        "inode": inode, 
                        "name": fname.strip(),
                        "is_deleted": is_deleted
                    })
    except Exception as e:
        print(f"Error running fls: {e}")
    return file_list

# --- API Routes ---

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        file_path = UPLOAD_DIR / file.filename
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        return {"filename": file.filename, "path": str(file_path)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"message": str(e)})

@app.post("/run/{filename}")
async def run_recovery(filename: str, background_tasks: BackgroundTasks):
    file_path = UPLOAD_DIR / filename
    if not file_path.exists():
        return JSONResponse(status_code=404, content={"message": "File not found"})
    if not TSK_RECOVER.exists():
        return JSONResponse(status_code=500, content={"message": "Sleuthkit binaries missing"})

    job_id = f"job_{int(time.time())}"
    jobs[job_id] = {"status": "running", "filename": filename, "progress": 0}
    
    background_tasks.add_task(execute_forensics, job_id, str(file_path))
    return {"job_id": job_id}

def execute_forensics(job_id: str, file_path: str):
    image_name = os.path.basename(file_path)
    output_dir = RECOVERED_DIR / f"recovered_{image_name}"
    
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # PHASE 1: Recovery
        jobs[job_id]["progress"] = 10
        subprocess.run([str(TSK_RECOVER), "-f", "fat32", "-e", file_path, str(output_dir)], check=True, capture_output=True)
        jobs[job_id]["progress"] = 50

        # PHASE 2: Analysis & Categorization
        files_metadata = []
        timeline_rows = []
        
        # Get true forensic status (deleted vs existing) from fls
        forensic_files = get_all_inodes(file_path)
        total_files = len(forensic_files)
        
        # Map filenames to deleted status for quick lookup
        deleted_map = {f["name"]: f["is_deleted"] for f in forensic_files}

        # Scan actual recovered files on disk to match them
        # We only process the first 50 files for speed in this demo
        processed_count = 0
        limit = 1000

        for root, _, filenames in os.walk(output_dir):
            for fname in filenames:
                if fname == "timeline.csv": continue
                
                full_path = Path(root) / fname
                rel_path = full_path.relative_to(output_dir)
                str_path = str(rel_path).replace("\\", "/") # normalize separators
                
                # Check if this file was marked as deleted in the image
                # (Simple string matching, might need adjustment for complex paths)
                is_recovered = False
                for f_name, deleted in deleted_map.items():
                    if fname in f_name: # loose match
                        is_recovered = deleted
                        break
                
                files_metadata.append({
                    "name": fname,
                    "path": str(rel_path),
                    "size": full_path.stat().st_size,
                    "category": "recovered" if is_recovered else "existing"
                })

                # Timeline generation (limit to first N for performance)
                if processed_count < limit:
                    # Find inode to run istat
                    inode = next((f["inode"] for f in forensic_files if f["name"].endswith(fname)), None)
                    if inode:
                        events = parse_istat(file_path, inode)
                        for event, ts in events:
                            timeline_rows.append({
                                "Date": ts.strftime("%Y-%m-%d %H:%M:%S"),
                                "Path": f'"{fname}"',
                                "Event": event
                            })
                    processed_count += 1
                    
                if processed_count % 5 == 0:
                     jobs[job_id]["progress"] = 50 + int((processed_count/limit)*40)

        # Save Metadata
        pd.DataFrame(timeline_rows).sort_values(by=["Date", "Path"], ascending=[True, True]).to_csv(output_dir / "timeline.csv", index=False)
        
        jobs[job_id]["status"] = "completed"
        jobs[job_id]["output_dir"] = str(output_dir)
        jobs[job_id]["files_data"] = files_metadata # Store list in memory for easy access
        jobs[job_id]["progress"] = 100

    except Exception as e:
        print(f"Error: {e}")
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)

@app.get("/status/{job_id}")
async def get_status(job_id: str):
    return jobs.get(job_id, {"status": "not_found"})

@app.get("/timeline/{job_id}")
async def get_timeline(job_id: str):
    job = jobs.get(job_id)
    if not job or job["status"] != "completed": return []
    csv_path = Path(job["output_dir"]) / "timeline.csv"
    if csv_path.exists():
         return pd.read_csv(csv_path).fillna("").to_dict(orient="records")
    return []

@app.get("/files/{job_id}")
async def list_files(job_id: str):
    job = jobs.get(job_id)
    if not job or job["status"] != "completed": return []
    return job.get("files_data", [])

@app.get("/download/{job_id}")
async def download_file(job_id: str, path: str):
    """Download a specific recovered file"""
    job = jobs.get(job_id)
    if not job: return JSONResponse(status_code=404, content={"message": "Job not found"})
    
    file_full_path = Path(job["output_dir"]) / path
    if not file_full_path.exists():
        return JSONResponse(status_code=404, content={"message": "File not found"})
        
    return FileResponse(file_full_path, filename=os.path.basename(path))

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)