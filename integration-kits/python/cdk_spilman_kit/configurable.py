import os
import yaml
import json
from typing import Dict, List, Any, Optional
from cdk_spilman import SpilmanBridge
from .host import BaseSpilmanHost
from .stores import SpilmanStores, SqliteSpilmanStores
from .keysets import refresh_keyset_cache

class ConfigurableSpilman:
    def __init__(
        self, 
        config: Dict[str, Any], 
        stores: SpilmanStores, 
        host: BaseSpilmanHost, 
        bridge: SpilmanBridge,
        spilman: Optional[Any] = None
    ):
        self.config = config
        self.stores = stores
        self.host = host
        self.bridge = bridge
        self.spilman = spilman

    @staticmethod
    def from_yaml(config_path: str, secret_key_hex: str) -> "ConfigurableSpilman":
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        # Support MINT_URL override like Rust/TS
        if "MINT_URL" in os.environ:
            mint_url = os.environ["MINT_URL"]
            all_units = list(config.get("pricing", {}).keys())
            config["mints"] = {mint_url: all_units}

        pricing = config.get("pricing", {})

        pricing_scale = config.get("pricing_scale", 1)
        try:
            pricing_scale = int(pricing_scale)
        except (TypeError, ValueError):
            pricing_scale = 1
        if pricing_scale <= 0:
            pricing_scale = 1
        config["pricing_scale"] = pricing_scale

        # Initialize stores
        storage_cfg = config.get("storage", {})
        if storage_cfg.get("type") == "sqlite" and storage_cfg.get("path"):
            stores = SqliteSpilmanStores(storage_cfg["path"])
        else:
            stores = SpilmanStores()

        host = BaseSpilmanHost(
            secret_key=secret_key_hex,
            mints=config.get("mints", {}),
            pricing=pricing,
            stores=stores,
            min_expiry_seconds=config.get("min_expiry_seconds", 3600),
            pricing_scale=pricing_scale,
        )

        bridge = SpilmanBridge(host)
        
        instance = ConfigurableSpilman(config, stores, host, bridge)
        
        # Initial keyset refresh
        instance.initialize_keysets()
        
        return instance

    def initialize_keysets(self):
        for mint_url in self.config.get("mints", {}).keys():
            try:
                self.host.refresh_all_keysets(mint_url)
            except Exception as e:
                print(f"WARNING: Failed to fetch keysets from {mint_url}: {e}")

    def init_flask(self, app):
        from .ext.flask import Spilman
        self.spilman = Spilman(app, self.host, self.bridge)
        return self.spilman
