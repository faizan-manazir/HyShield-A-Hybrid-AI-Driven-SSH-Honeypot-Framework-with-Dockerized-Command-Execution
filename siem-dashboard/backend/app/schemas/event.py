from pydantic import BaseModel, ConfigDict
from typing import Optional, Any, Dict, List

class CowrieEventBase(BaseModel):
    model_config = ConfigDict(extra='allow')
    eventid: str
    timestamp: str
    session: Optional[str] = None
    src_ip: Optional[str] = None
    sensor: Optional[str] = None
