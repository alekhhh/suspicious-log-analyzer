from pathlib import Path

from log_types import Detection


class AlertSystem:
    def __init__(self, output_target: str = "stdout"):
        self.output_target = output_target

    def emit(self, detections: list[Detection]) -> None:
        if not detections:
            self._write("No alerts generated.\n")
            return

        for d in detections:
            line = (
                f"[ALERT] {d.severity.upper()} | {d.kind} | "
                f"{d.timestamp.isoformat(sep=' ')} | {d.message}\n"
            )
            self._write(line)

    def _write(self, text: str) -> None:
        if self.output_target == "stdout":
            print(text, end="")
            return

        path = Path(self.output_target)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(text)
