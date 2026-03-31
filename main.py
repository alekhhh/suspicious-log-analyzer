from alerter import AlertSystem
from config import AppConfig
from detector import DetectionConfig, DetectionEngine
from parser import parse_log_directory
from reporter import build_report_rows, write_report_csv


def main() -> None:
    app_config = AppConfig()

    events, invalid_lines = parse_log_directory(app_config.input_dir)

    config = DetectionConfig(
        failed_limit=app_config.failed_limit,
        brute_force_user_limit=app_config.brute_force_user_limit,
        brute_force_ip_limit=app_config.brute_force_ip_limit,
        unusual_start_hour=app_config.unusual_start_hour,
        unusual_end_hour=app_config.unusual_end_hour,
        burst_window_minutes=app_config.burst_window_minutes,
    )
    engine = DetectionEngine(config=config)
    detections = engine.analyze(events)

    alert_system = AlertSystem(output_target=app_config.alert_output)
    alert_system.emit(detections)

    report_rows = build_report_rows(events, detections)
    write_report_csv(report_rows, app_config.report_output_csv)

    print(f"\nCSV report written to: {app_config.report_output_csv}")
    if invalid_lines:
        print(f"Skipped invalid lines: {len(invalid_lines)}")


if __name__ == "__main__":
    main()
