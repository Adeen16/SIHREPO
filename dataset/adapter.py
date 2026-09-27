from abc import ABC, abstractmethod
from typing import Iterator
from dataset.schema import ExternalDatasetRecord, CanonicalLabel

class DatasetAdapter(ABC):
    """
    Base class for adapting specific datasets (e.g., CIC-IDS2018, CTU-13)
    into the ExternalDatasetRecord schema.
    """

    def __init__(self, dataset_name: str, file_path: str):
        self.dataset_name = dataset_name
        self.file_path = file_path

    @abstractmethod
    def get_records(self) -> Iterator[ExternalDatasetRecord]:
        """
        Parses the dataset and yields ExternalDatasetRecord objects in chronological order.
        """
        pass

    @abstractmethod
    def map_label(self, original_label: str) -> CanonicalLabel:
        """
        Maps a dataset-specific label to a CanonicalLabel.
        Must explicitly handle unknown labels by returning CanonicalLabel.UNKNOWN
        and avoiding fabricated mappings.
        """
        pass
