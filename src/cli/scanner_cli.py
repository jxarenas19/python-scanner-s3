#!/usr/bin/env python3
"""
Scanner CLI Interface
Command-line interface for scanner operations
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.scanner_service import (
    DeviceBusyError,
    HardwareError,
    NoScannerError,
    ScanFailedError,
    ScannerService,
)


class ScannerCLI:
    """Command-line interface for scanner operations"""

    def __init__(self):
        self.scanner_service = ScannerService()
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command-line argument parser"""
        parser = argparse.ArgumentParser(
            prog="scanner-cli",
            description="Document Scanner CLI Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  scanner-cli status                     # Check scanner availability
  scanner-cli scan                       # Scan a document
  scanner-cli scan --emergency           # Emergency scan mode
  scanner-cli diagnostics                # Run scanner diagnostics
  scanner-cli health                     # Show scanner health status
  scanner-cli calibrate                  # Calibrate scanner
            """,
        )

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Status command
        status_parser = subparsers.add_parser(
            "status", help="Check scanner availability"
        )
        status_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Scan a document")
        scan_parser.add_argument(
            "--emergency",
            action="store_true",
            help="Enable emergency mode (bypass some checks)",
        )
        scan_parser.add_argument(
            "--output", "-o", help="Output directory for scanned document"
        )
        scan_parser.add_argument(
            "--json", action="store_true", help="Output result in JSON format"
        )

        # Diagnostics command
        diag_parser = subparsers.add_parser(
            "diagnostics", help="Run scanner diagnostics"
        )
        diag_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Health command
        health_parser = subparsers.add_parser(
            "health", help="Show scanner health status"
        )
        health_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Calibrate command
        calib_parser = subparsers.add_parser("calibrate", help="Calibrate scanner")
        calib_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Error analysis command
        errors_parser = subparsers.add_parser("errors", help="Analyze error patterns")
        errors_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        return parser

    def run(self, args: list = None) -> int:
        """
        Run the CLI with given arguments

        Args:
            args: Command line arguments (uses sys.argv if None)

        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            parsed_args = self.parser.parse_args(args)

            if not parsed_args.command:
                self.parser.print_help()
                return 1

            # Route to appropriate handler
            handler_map = {
                "status": self._handle_status,
                "scan": self._handle_scan,
                "diagnostics": self._handle_diagnostics,
                "health": self._handle_health,
                "calibrate": self._handle_calibrate,
                "errors": self._handle_errors,
            }

            handler = handler_map.get(parsed_args.command)
            if handler:
                return handler(parsed_args)
            else:
                print(f"Unknown command: {parsed_args.command}", file=sys.stderr)
                return 1

        except KeyboardInterrupt:
            print("\nOperation cancelled by user", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    def _handle_status(self, args) -> int:
        """Handle scanner status command"""
        try:
            result = self.scanner_service.check_scanner_availability()

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_status(result)

            return 0

        except Exception as e:
            self._print_error("Failed to check scanner status", e, args.json)
            return 1

    def _print_status(self, result: dict) -> None:
        """Print scanner status in human-readable format"""
        print("=== Scanner Status ===")

        if result["available"]:
            print(f"✅ Scanner Available: {result['scanner_name']}")
            print(f"   Driver Version: {result.get('driver_version', 'Unknown')}")

            if "driver_status" in result and result["driver_status"]["outdated"]:
                print(f"⚠️  Driver Update Available:")
                print(f"   Current: {result['driver_status']['current_version']}")
                print(
                    f"   Recommended: {result['driver_status']['recommended_version']}"
                )
                print(f"   Update URL: {result['driver_status']['update_url']}")
        else:
            print(f"❌ Scanner Not Available: {result['scanner_name']}")

            if "reconnection_steps" in result:
                print("\n🔧 Reconnection Steps:")
                for i, step in enumerate(result["reconnection_steps"], 1):
                    print(f"   {i}. {step}")

    def _handle_scan(self, args) -> int:
        """Handle document scan command"""
        try:
            print("🔍 Starting document scan...")

            # Perform scan
            result = self.scanner_service.scan_document(emergency_mode=args.emergency)

            # Handle output directory
            if args.output:
                output_dir = Path(args.output)
                output_dir.mkdir(parents=True, exist_ok=True)

                # Move scanned file to output directory
                original_path = Path(result["document_path"])
                new_path = output_dir / original_path.name
                original_path.rename(new_path)
                result["document_path"] = str(new_path)

            if args.json:
                # Convert datetime to ISO string for JSON serialization
                result_copy = result.copy()
                if isinstance(result_copy["timestamp"], datetime):
                    result_copy["timestamp"] = result_copy["timestamp"].isoformat()
                print(json.dumps(result_copy, indent=2))
            else:
                self._print_scan_result(result)

            return 0

        except NoScannerError as e:
            self._print_error("No scanner available", e, args.json)
            return 1
        except DeviceBusyError as e:
            self._print_error("Scanner is busy", e, args.json)
            return 1
        except ScanFailedError as e:
            self._print_error("Scan operation failed", e, args.json)
            return 1
        except HardwareError as e:
            self._print_hardware_error(e, args.json)
            return 1
        except Exception as e:
            self._print_error("Unexpected error during scan", e, args.json)
            return 1

    def _print_scan_result(self, result: dict) -> None:
        """Print scan result in human-readable format"""
        print("✅ Document scanned successfully!")
        print(f"   Document Path: {result['document_path']}")
        print(f"   Format: {result['format']}")
        print(f"   File Size: {result['file_size']:,} bytes")
        print(f"   Scan Time: {result['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")

        # Additional information
        if "retry_info" in result:
            retry_info = result["retry_info"]
            print(f"   Retry Attempts: {retry_info['total_attempts']}")

        if "quality_score" in result:
            print(f"   Quality Score: {result['quality_score']}%")

        if "emergency_mode_used" in result and result["emergency_mode_used"]:
            print("⚠️  Emergency mode was used - some checks were bypassed")

    def _handle_diagnostics(self, args) -> int:
        """Handle scanner diagnostics command"""
        try:
            print("🔬 Running scanner diagnostics...")

            result = self.scanner_service.run_diagnostics()

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_diagnostics(result)

            return 0

        except Exception as e:
            self._print_error("Failed to run diagnostics", e, args.json)
            return 1

    def _print_diagnostics(self, result: dict) -> None:
        """Print diagnostics in human-readable format"""
        print("=== Scanner Diagnostics ===")

        # Hardware status
        hw_status = result.get("hardware_status", {})
        print(f"\n📱 Hardware Status:")
        print(f"   Connection: {hw_status.get('connection', 'Unknown')}")
        print(f"   Lamp Status: {hw_status.get('lamp_status', 'Unknown')}")
        print(f"   Sensor Status: {hw_status.get('sensor_status', 'Unknown')}")
        print(f"   Calibration: {hw_status.get('calibration_status', 'Unknown')}")

        # Driver info
        driver_info = result.get("driver_info", {})
        print(f"\n🔧 Driver Information:")
        print(f"   Version: {driver_info.get('version', 'Unknown')}")
        print(f"   Compatibility: {driver_info.get('compatibility', 'Unknown')}")

        # Performance metrics
        perf_metrics = result.get("performance_metrics", {})
        print(f"\n📊 Performance Metrics:")
        print(f"   Scan Speed: {perf_metrics.get('scan_speed', 'Unknown')}")
        print(f"   Quality Score: {perf_metrics.get('quality_score', 'Unknown')}")

        # Recent errors
        recent_errors = result.get("recent_errors", [])
        if recent_errors:
            print(f"\n⚠️  Recent Errors ({len(recent_errors)}):")
            for error in recent_errors[-5:]:  # Show last 5 errors
                print(f"   - {error}")
        else:
            print(f"\n✅ No recent errors")

    def _handle_health(self, args) -> int:
        """Handle scanner health command"""
        try:
            result = self.scanner_service.get_health_status()

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_health(result)

            return 0

        except Exception as e:
            self._print_error("Failed to get health status", e, args.json)
            return 1

    def _print_health(self, result: dict) -> None:
        """Print health status in human-readable format"""
        print("=== Scanner Health Status ===")

        health_score = result.get("health_score", 0)
        status = result.get("status", "unknown")

        # Health indicator
        if status == "healthy":
            indicator = "✅"
        elif status == "warning":
            indicator = "⚠️"
        else:
            indicator = "❌"

        print(f"\n{indicator} Overall Health: {health_score}/100 ({status.upper()})")
        print(f"   Success Rate: {result.get('scan_success_rate', 0):.1%}")
        print(f"   Average Scan Time: {result.get('average_scan_time', 0):.2f}s")
        print(f"   Uptime: {result.get('uptime', 0):.0f} seconds")
        print(f"   Trend: {result.get('trend', 'unknown').title()}")

    def _handle_calibrate(self, args) -> int:
        """Handle scanner calibration command"""
        try:
            print("🔧 Calibrating scanner...")

            result = self.scanner_service.recalibrate_scanner()

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_calibration_result(result)

            return 0

        except HardwareError as e:
            self._print_error("Calibration failed", e, args.json)
            return 1
        except Exception as e:
            self._print_error("Unexpected error during calibration", e, args.json)
            return 1

    def _print_calibration_result(self, result: dict) -> None:
        """Print calibration result in human-readable format"""
        if result.get("calibration_successful", False):
            print("✅ Scanner calibration completed successfully!")

            cal_data = result.get("calibration_data", {})
            if cal_data:
                print("   Calibration Data:")
                for key, value in cal_data.items():
                    print(f"     {key.replace('_', ' ').title()}: {value}")
        else:
            print("❌ Scanner calibration failed")

    def _handle_errors(self, args) -> int:
        """Handle error pattern analysis command"""
        try:
            result = self.scanner_service.analyze_error_patterns()

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_error_analysis(result)

            return 0

        except Exception as e:
            self._print_error("Failed to analyze error patterns", e, args.json)
            return 1

    def _print_error_analysis(self, result: dict) -> None:
        """Print error analysis in human-readable format"""
        print("=== Error Pattern Analysis ===")

        if result.get("pattern_detected", False):
            print("\n⚠️  Error patterns detected:")

            frequent_errors = result.get("frequent_errors", [])
            for error in frequent_errors:
                print(f"   - {error['type']}: {error['count']} occurrences")

            recommendations = result.get("recommended_actions", [])
            if recommendations:
                print("\n💡 Recommended Actions:")
                for i, action in enumerate(recommendations, 1):
                    print(f"   {i}. {action}")
        else:
            print("\n✅ No significant error patterns detected")

    def _print_error(
        self, message: str, error: Exception, json_output: bool = False
    ) -> None:
        """Print error message in appropriate format"""
        if json_output:
            error_data = {
                "error": True,
                "message": message,
                "details": str(error),
                "error_code": getattr(error, "error_code", "UNKNOWN_ERROR"),
                "timestamp": datetime.now().isoformat(),
            }
            print(json.dumps(error_data, indent=2))
        else:
            print(f"❌ {message}: {error}", file=sys.stderr)

    def _print_hardware_error(
        self, error: HardwareError, json_output: bool = False
    ) -> None:
        """Print hardware error with recovery instructions"""
        if json_output:
            error_data = {
                "error": True,
                "message": "Hardware error",
                "details": str(error),
                "error_code": error.error_code,
                "recovery_suggestion": error.recovery_suggestion,
                "recovery_instructions": getattr(error, "recovery_instructions", []),
                "timestamp": datetime.now().isoformat(),
            }
            print(json.dumps(error_data, indent=2))
        else:
            print(f"❌ Hardware Error: {error}", file=sys.stderr)
            print(f"💡 {error.recovery_suggestion}", file=sys.stderr)

            if hasattr(error, "recovery_instructions") and error.recovery_instructions:
                print("🔧 Recovery Steps:", file=sys.stderr)
                for i, step in enumerate(error.recovery_instructions, 1):
                    print(f"   {i}. {step}", file=sys.stderr)


def main():
    """Main entry point for scanner CLI"""
    cli = ScannerCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
