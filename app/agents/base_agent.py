from abc import ABC, abstractmethod
from app.state import ArgusState


class BaseAgent(ABC):

    @abstractmethod
    def run(self, state: ArgusState) -> ArgusState:
        pass