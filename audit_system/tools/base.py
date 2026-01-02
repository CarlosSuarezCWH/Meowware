from abc import ABC, abstractmethod
from typing import Any, Dict

class BaseTool(ABC):
    def __init__(self):
        self.available = True

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def is_available(self) -> bool:
        """Check if the tool's binary/dependency is available."""
        import shutil
        return shutil.which(self.name) is not None

    @abstractmethod
    def run(self, target: Any) -> Dict[str, Any]:
        """
        Execute the tool against the target.
        Returns the raw output or a structured intermediate dict.
        """
        pass
