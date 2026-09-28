import pytest
from common.blind_guard import TrainingGuard

def test_blind_guard_blocks_pcap():
    guard = TrainingGuard()
    
    # Should block
    with pytest.raises(ValueError, match="BLOCKED"):
        guard.check_file("NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap")
        
    # Should pass
    guard.check_file("NTRO-Datasets/CSE-CIC-IDS2018/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv")
