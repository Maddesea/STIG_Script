"""Plugin and Hook architecture for STIG Assessor."""

import importlib.util
import inspect
from pathlib import Path
from typing import Any, Callable

from stig_assessor.core.config import Cfg
from stig_assessor.core.logging import LOG


class PluginManager:
    """Manages dynamic loading and execution of custom Python plugins."""

    _instance = None
    _hooks: dict
    _loaded: bool

    def __new__(cls) -> "PluginManager":
        """Instantiate single-instance PluginManager object."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._hooks = {
                "post_ckl_create": [],
                "pre_apply_results": [],
                "post_stats_generate": [],
            }
            cls._instance._loaded = False
        return cls._instance

    def load_plugins(self, disable: bool = False) -> None:
        """Discover and load external Python plugins from the plugin directory.

        Searches the standard `~/.stig_assessor/plugins/` directory for `.py` files
        and automatically mounts their internal hooks if `register_hooks` is defined.

        Args:
            disable: If True, bypass plugin loading entirely.
        """
        if self._loaded or disable:
            return

        plugin_dir = Cfg.APP_DIR / "plugins"
        plugin_dir.mkdir(parents=True, exist_ok=True)

        plugins_found = list(plugin_dir.glob("*.py"))
        for p in plugins_found:
            try:
                self._load_module(p)
            except Exception as e:
                LOG.e(f"Failed to load plugin {p.name}: {e}")

        self._loaded = True

    def _load_module(self, path: Path) -> None:
        """Load a single Python module and register its hooks.

        Args:
            path: Absolute path to the python code module.
        """
        spec = importlib.util.spec_from_file_location(path.stem, str(path))
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Look for hook registration
            if hasattr(module, "register_hooks"):
                hooks = module.register_hooks()
                for hook_name, func in hooks.items():
                    self.register(hook_name, func)
                LOG.i(f"Loaded plugin '{path.stem}' with {len(hooks)} hooks.")

    def register(self, hook_name: str, func: Callable) -> None:
        """Register a function to a specific hook.

        Args:
            hook_name: The internal string dictionary identifier of the hook.
            func: Execution callback function.
        """
        if hook_name not in self._hooks:
            self._hooks[hook_name] = []
        self._hooks[hook_name].append(func)

    def run_hooks(self, hook_name: str, *args, **kwargs) -> Any:
        """Execute all functions registered to a hook.

        The result of each hook is passed to the next (if it's a pipeline hook).
        Otherwise just fires identically across all.

        Args:
            hook_name: Identifier string of the hook mapping to trigger.
            *args: Positional arguments bubbled down dynamically to plugin.
            **kwargs: Keyword arguments containing context (such as 'payload').

        Returns:
            The processed result object matching the format of 'payload' keyword argument,
            or None if no payload modifier exists.
        """
        if hook_name not in self._hooks or not self._hooks[hook_name]:
            # For pipeline hooks returning the processed object
            if kwargs.get("payload"):
                return kwargs.get("payload")
            return None

        LOG.d(f"Running {len(self._hooks[hook_name])} hooks for {hook_name}")
        payload = kwargs.get("payload", None)

        for func in self._hooks[hook_name]:
            try:
                sig = inspect.signature(func)
                # If it takes a payload, we pass it and overwrite it (pipeline)
                if "payload" in sig.parameters:
                    res = func(
                        payload=payload,
                        *args,
                        **{k: v for k, v in kwargs.items() if k != "payload"},
                    )
                    if res is not None:
                        payload = res
                else:
                    func(*args, **kwargs)
            except Exception as e:
                LOG.e(f"Hook '{hook_name}' execution failed: {e}")

        return payload
