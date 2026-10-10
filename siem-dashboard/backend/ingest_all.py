import os
from app.services.event_processor import EventProcessor

def ingest_all():
    file_path = "cowrie.json"
    if not os.path.exists(file_path):
        print("File not found.")
        return
        
    processor = EventProcessor()
    
    with open(file_path, "r", encoding="utf-8") as f:
        # read in chunks to avoid memory issues if file is huge
        lines = f.readlines()
        print(f"Read {len(lines)} lines from {file_path}. Processing...")
        processor.process_lines(lines)
        print("Processing complete.")

if __name__ == "__main__":
    ingest_all()
