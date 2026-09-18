from abc import ABC, abstractmethod
from typing import List, Optional
from sentinel_ids.core.packet import ParsedPacket
from sentinel_ids.core.flow import FlowTracker, Flow
from sentinel_ids.alerts import Alert


class BaseDetector(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def analyze(self, packet: ParsedPacket, flow: Optional[Flow], tracker: FlowTracker) -> List[Alert]:
        pass
