import re
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd

app = FastAPI(title="Log Analyzer API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Nginx/Apache Access Log lines Analyze කිරීමට අවශ්‍ය Regex Pattern එකsample_access.log
LOG_PATTERN = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD) (.*?) HTTP/.*?" (\d{3})'

@app.get("/")
def read_root():
    return {"message": "Cybersecurity Log Analyzer API is Running!"}

@app.post("/api/analyze")
async def analyze_log_file(file: UploadFile = File(...)):
    contents = await file.read()
    log_text = contents.decode("utf-8")
    
    parsed_logs = []
    
    # PARSE THE LOG LINE BY LINE USING REGEX
    for line in log_text.splitlines():
        match = re.match(LOG_PATTERN, line)
        if match:
            ip, timestamp, method, endpoint, status_code = match.groups()
            parsed_logs.append({
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "endpoint": endpoint,
                "status_code": int(status_code)
            })
            
    if not parsed_logs:
        return {"error": "Invalid or incompatible log file format."}
        
    # USE PANDAS DATAFRAME FOR ANALYSIS
    df = pd.DataFrame(parsed_logs)
    
    # 1. Top IP Addresses
    top_ips = df['ip'].value_counts().head(5).to_dict()
    
    # 2. HTTP Status Code Breakdown
    status_counts = df['status_code'].value_counts().to_dict()
    
    # 3. Security Warning: Potential Brute Force Alerts (Multiple 401s from same IP)
    unauthorized_df = df[df['status_code'] == 401]
    suspicious_ips = unauthorized_df['ip'].value_counts()
    brute_force_alerts = suspicious_ips[suspicious_ips >= 3].to_dict()
    
    return {
        "total_requests": len(df),
        "top_ips": top_ips,
        "status_codes": status_counts,
        "security_alerts": {
            "potential_brute_force_ips": brute_force_alerts
        }
    }