import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

class Config:
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or os.path.expanduser("~/.netsectoolkit/config.json")
        self.config_dir = os.path.dirname(self.config_file)
        self.config = self._load_default_config()
        self._load_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        return {
            "scanner": {
                "timeout": 2.0,
                "max_threads": 100,
                "default_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
            },
            "analyzer": {
                "capture_timeout": 60,
                "max_packets": 10000,
                "default_interface": None
            },
            "detector": {
                "timeout": 3.0,
                "check_credentials": True,
                "export_format": "json"
            },
            "logging": {
                "level": "INFO",
                "file": None,
                "console": True
            }
        }
    
    def _load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    saved_config = json.load(f)
                    self._merge_config(self.config, saved_config)
        except Exception as e:
            print(f"Warning: Failed to load config file: {e}")
    
    def _merge_config(self, base: Dict, override: Dict):
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def save(self):
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save config file: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
    
    def get_scanner_config(self) -> Dict[str, Any]:
        return self.config.get("scanner", {})
    
    def get_analyzer_config(self) -> Dict[str, Any]:
        return self.config.get("analyzer", {})
    
    def get_detector_config(self) -> Dict[str, Any]:
        return self.config.get("detector", {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        return self.config.get("logging", {})
    
    def reset(self):
        self.config = self._load_default_config()