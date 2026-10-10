import os
import time
import json
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)

class CowrieLogHandler(FileSystemEventHandler):
    def __init__(self, file_path, process_callback):
        self.file_path = file_path
        self.process_callback = process_callback
        self.offset = 0
        
        # Initialize offset if file exists (skip old logs on startup)
        if os.path.exists(self.file_path):
            self.offset = os.path.getsize(self.file_path)
            logger.info(f"Initialized log watcher at offset {self.offset}")

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == os.path.abspath(self.file_path):
            self.read_new_lines()

    def read_new_lines(self):
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                f.seek(self.offset)
                new_lines = f.readlines()
                self.offset = f.tell()
                
                if new_lines:
                    self.process_callback(new_lines)
        except Exception as e:
            logger.error(f"Error reading log file: {e}")

class LogWatcher:
    def __init__(self, file_path, process_callback):
        self.file_path = os.path.abspath(file_path)
        self.process_callback = process_callback
        self.observer = None

    def start(self):
        dir_path = os.path.dirname(self.file_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
            
        if not os.path.exists(self.file_path):
            with open(self.file_path, "w") as f:
                pass # create empty file
                
        handler = CowrieLogHandler(self.file_path, self.process_callback)
        self.observer = Observer()
        self.observer.schedule(handler, dir_path, recursive=False)
        self.observer.start()
        logger.info(f"Started watching {self.file_path}")

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.info("Stopped log watcher")
