import pytest
import yaml
from ml.blind_guard import assert_not_blind, is_blind, load_manifest

def test_blind_guard(tmp_path):
    manifest = tmp_path / "captures.yaml"
    data = {
        "captures": [
            {"sha256": "blind_hash", "role": "blind"},
            {"sha256": "val_hash", "role": "validation"}
        ]
    }
    manifest.write_text(yaml.dump(data))

    load_manifest(str(manifest))
    
    assert is_blind("blind_hash", str(manifest))
    assert not is_blind("val_hash", str(manifest))
    
    with pytest.raises(ValueError, match="Blind guard violation"):
        assert_not_blind("blind_hash", str(manifest))
        
    assert_not_blind("val_hash", str(manifest))  # Should not raise
