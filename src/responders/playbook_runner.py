"""Execute response playbooks defined in YAML configuration files."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from src.analyzers.alert_classifier import AlertCategory, ClassificationResult
from src.analyzers.correlation import SecurityAlert

logger = logging.getLogger(__name__)


@dataclass
class PlaybookStep:
    """A single step in a response playbook."""

    name: str
    action: str
    parameters: dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None
    on_failure: str = "continue"


@dataclass
class Playbook:
    """A response playbook with ordered steps."""

    name: str
    description: str
    category: str
    severity_threshold: str
    steps: list[PlaybookStep]
    tags: list[str] = field(default_factory=list)


@dataclass
class PlaybookResult:
    """Result of executing a playbook."""

    playbook_name: str
    success: bool
    steps_executed: int
    steps_total: int
    results: list[dict[str, Any]]
    errors: list[str]


class PlaybookRunner:
    """Loads and executes YAML-defined response playbooks.

    Playbooks define a series of response actions to take when specific
    alert categories are detected. Actions are mapped to handler functions
    registered at runtime.
    """

    def __init__(self, playbook_directory: str = "./playbooks") -> None:
        self.playbook_dir = Path(playbook_directory)
        self._playbooks: dict[str, Playbook] = {}
        self._action_handlers: dict[str, Callable[..., dict[str, Any]]] = {}
        self._load_playbooks()

    def _load_playbooks(self) -> None:
        """Load all YAML playbook files from the configured directory."""
        if not self.playbook_dir.exists():
            logger.warning("Playbook directory does not exist: %s", self.playbook_dir)
            return

        for yaml_file in self.playbook_dir.glob("*.yaml"):
            try:
                with open(yaml_file, "r") as f:
                    data = yaml.safe_load(f)

                if not data:
                    continue

                steps = []
                for step_data in data.get("steps", []):
                    steps.append(PlaybookStep(
                        name=step_data.get("name", ""),
                        action=step_data.get("action", ""),
                        parameters=step_data.get("parameters", {}),
                        condition=step_data.get("condition"),
                        on_failure=step_data.get("on_failure", "continue"),
                    ))

                playbook = Playbook(
                    name=data.get("name", yaml_file.stem),
                    description=data.get("description", ""),
                    category=data.get("category", ""),
                    severity_threshold=data.get("severity_threshold", "medium"),
                    steps=steps,
                    tags=data.get("tags", []),
                )

                self._playbooks[playbook.category] = playbook
                logger.info("Loaded playbook: %s (%s)", playbook.name, yaml_file.name)

            except Exception:
                logger.exception("Failed to load playbook: %s", yaml_file)

    def register_action(self, action_name: str, handler: Callable[..., dict[str, Any]]) -> None:
        """Register a handler function for a playbook action type.

        Args:
            action_name: The action identifier used in playbook YAML.
            handler: Function that executes the action. Receives (alert, parameters) arguments.
        """
        self._action_handlers[action_name] = handler

    def run(
        self,
        alert: SecurityAlert,
        classification: ClassificationResult,
    ) -> Optional[PlaybookResult]:
        """Execute the appropriate playbook for a classified alert.

        Args:
            alert: The security alert to respond to.
            classification: The LLM classification result.

        Returns:
            PlaybookResult if a matching playbook was found and executed, else None.
        """
        playbook = self._playbooks.get(classification.category.value)
        if not playbook:
            logger.info("No playbook found for category: %s", classification.category.value)
            return None

        logger.info("Running playbook '%s' for alert %s", playbook.name, alert.alert_id)

        results: list[dict[str, Any]] = []
        errors: list[str] = []
        steps_executed = 0

        for step in playbook.steps:
            if step.condition and not self._evaluate_condition(step.condition, alert, classification):
                logger.debug("Skipping step '%s' (condition not met)", step.name)
                continue

            handler = self._action_handlers.get(step.action)
            if not handler:
                error_msg = f"No handler registered for action '{step.action}'"
                logger.warning(error_msg)
                errors.append(error_msg)
                if step.on_failure == "abort":
                    break
                continue

            try:
                result = handler(alert, step.parameters)
                results.append({"step": step.name, "action": step.action, "result": result})
                steps_executed += 1
            except Exception as e:
                error_msg = f"Step '{step.name}' failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
                if step.on_failure == "abort":
                    break

        return PlaybookResult(
            playbook_name=playbook.name,
            success=len(errors) == 0,
            steps_executed=steps_executed,
            steps_total=len(playbook.steps),
            results=results,
            errors=errors,
        )

    def get_available_playbooks(self) -> list[str]:
        """Return a list of available playbook categories."""
        return list(self._playbooks.keys())

    def _evaluate_condition(
        self,
        condition: str,
        alert: SecurityAlert,
        classification: ClassificationResult,
    ) -> bool:
        """Evaluate a simple playbook step condition."""
        safe_context = {
            "severity": classification.severity.value,
            "confidence": classification.confidence,
            "false_positive_likelihood": classification.false_positive_likelihood,
            "alert_source": alert.source,
        }
        try:
            return bool(eval(condition, {"__builtins__": {}}, safe_context))
        except Exception:
            logger.warning("Failed to evaluate condition: %s", condition)
            return False
