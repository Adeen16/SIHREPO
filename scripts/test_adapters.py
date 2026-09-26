import json
from dataset import CICIDS2018Adapter, CTU13Adapter

def test_cic():
    print("Testing CIC-IDS2018 Adapter")
    adapter = CICIDS2018Adapter("CIC-IDS2018", r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CSE-CIC-IDS2018\Friday-02-03-2018_TrafficForML_CICFlowMeter.csv")
    records = adapter.get_records()
    for i in range(2):
        print(next(records))
        
def test_ctu():
    print("\nTesting CTU-13 Adapter")
    adapter = CTU13Adapter("CTU-13", r"C:\Users\ADEEN\workspace\SIH145\NTRO-Datasets\CTU-13\CTU-Malware-Capture-Botnet-42.binetflow")
    records = adapter.get_records()
    for i in range(2):
        print(next(records))

if __name__ == "__main__":
    test_cic()
    test_ctu()
