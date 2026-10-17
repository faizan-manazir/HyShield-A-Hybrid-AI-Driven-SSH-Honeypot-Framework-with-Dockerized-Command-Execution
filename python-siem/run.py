"""Start the dashboard:  python run.py"""
import uvicorn

from app import config

if __name__ == "__main__":
    print(f"\n  HyShield SIEM  ->  http://{config.HOST}:{config.PORT}\n  Reading log    ->  {config.LOG_PATH}\n")
    uvicorn.run("app.main:app", host=config.HOST, port=config.PORT)
