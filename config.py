from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    input_dir: str = "input_logs"
    report_output_csv: str = "report.csv"
    alert_output: str = "stdout"

    failed_limit: int = 5
    brute_force_user_limit: int = 4
    brute_force_ip_limit: int = 4
    unusual_start_hour: int = 0
    unusual_end_hour: int = 5
    burst_window_minutes: int = 10
