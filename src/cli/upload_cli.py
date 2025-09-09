#!/usr/bin/env python3
"""
Upload CLI Interface
Command-line interface for S3 upload operations
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.upload_service import (
    InsufficientDiskSpaceError,
    NetworkConnectionError,
    RetryExhaustedException,
    S3AccessDeniedError,
    UploadService,
    UploadTimeoutError,
)


class UploadCLI:
    """Command-line interface for S3 upload operations"""

    def __init__(self):
        self.upload_service = UploadService()
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command-line argument parser"""
        parser = argparse.ArgumentParser(
            prog="upload-cli",
            description="S3 Upload CLI Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  upload-cli upload document.enc admin sucursal-centro     # Upload encrypted document
  upload-cli upload document.enc admin sucursal-centro --timestamp "2024-01-15T10:30:00"
  upload-cli health                                        # Check network health
  upload-cli stats                                         # Show upload statistics
  upload-cli config                                        # Show S3 configuration
  upload-cli estimate document.enc                         # Estimate upload time
            """,
        )

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Upload command
        upload_parser = subparsers.add_parser(
            "upload", help="Upload encrypted document to S3"
        )
        upload_parser.add_argument(
            "encrypted_file", help="Path to encrypted document file"
        )
        upload_parser.add_argument("operator", help="Operator name")
        upload_parser.add_argument("branch", help="Branch name")
        upload_parser.add_argument("--timestamp", help="Custom timestamp (ISO format)")
        upload_parser.add_argument(
            "--session-token", help="Session token for authentication"
        )
        upload_parser.add_argument(
            "--json", action="store_true", help="Output result in JSON format"
        )
        upload_parser.add_argument(
            "--no-cleanup",
            action="store_true",
            help="Do not delete local file after successful upload",
        )

        # Health command
        health_parser = subparsers.add_parser(
            "health", help="Check network health status"
        )
        health_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Statistics command
        stats_parser = subparsers.add_parser("stats", help="Show upload statistics")
        stats_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Configuration command
        config_parser = subparsers.add_parser("config", help="Show S3 configuration")
        config_parser.add_argument(
            "--validate", action="store_true", help="Validate configuration"
        )
        config_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Estimate command
        estimate_parser = subparsers.add_parser("estimate", help="Estimate upload time")
        estimate_parser.add_argument("file_path", help="Path to file for estimation")
        estimate_parser.add_argument(
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
                "upload": self._handle_upload,
                "health": self._handle_health,
                "stats": self._handle_stats,
                "config": self._handle_config,
                "estimate": self._handle_estimate,
            }

            handler = handler_map.get(parsed_args.command)
            if handler:
                return handler(parsed_args)
            else:
                print(f"Unknown command: {parsed_args.command}", file=sys.stderr)
                return 1

        except KeyboardInterrupt:
            print("\nUpload cancelled by user", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    def _handle_upload(self, args) -> int:
        """Handle document upload command"""
        try:
            # Validate file exists
            encrypted_file = Path(args.encrypted_file)
            if not encrypted_file.exists():
                print(
                    f"Error: Encrypted file not found: {args.encrypted_file}",
                    file=sys.stderr,
                )
                return 1

            # Validate file is encrypted
            if not encrypted_file.suffix == ".enc":
                print(f"Warning: File doesn't have .enc extension", file=sys.stderr)

            # Parse timestamp
            if args.timestamp:
                try:
                    timestamp = datetime.fromisoformat(args.timestamp)
                except ValueError:
                    print(
                        f"Error: Invalid timestamp format. Use ISO format (YYYY-MM-DDTHH:MM:SS)",
                        file=sys.stderr,
                    )
                    return 1
            else:
                timestamp = datetime.now()

            print(f"☁️  Uploading document to S3: {encrypted_file.name}")
            print(f"   Operator: {args.operator}")
            print(f"   Branch: {args.branch}")
            print(f"   Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   File Size: {encrypted_file.stat().st_size:,} bytes")

            if args.session_token:
                print(f"   Session: {args.session_token[:16]}...")

            # Perform upload
            result = self.upload_service.upload_encrypted_document(
                encrypted_file_path=str(encrypted_file),
                operator=args.operator,
                branch=args.branch,
                timestamp=timestamp,
                session_token=args.session_token,
            )

            # Clean up local file unless explicitly disabled
            if not args.no_cleanup:
                try:
                    encrypted_file.unlink()
                    result["local_file_deleted"] = True
                except Exception as e:
                    result["cleanup_warning"] = f"Could not delete local file: {e}"
            else:
                result["local_file_deleted"] = False

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_upload_result(result, args.no_cleanup)

            return 0

        except NetworkConnectionError as e:
            self._print_error("Network connection failed", e, args.json)
            return 1
        except UploadTimeoutError as e:
            self._print_error("Upload operation timed out", e, args.json)
            return 1
        except S3AccessDeniedError as e:
            self._print_error("S3 access denied", e, args.json)
            return 1
        except RetryExhaustedException as e:
            self._print_error("All retry attempts exhausted", e, args.json)
            return 1
        except InsufficientDiskSpaceError as e:
            self._print_error("Insufficient disk space", e, args.json)
            return 1
        except Exception as e:
            self._print_error("Unexpected error during upload", e, args.json)
            return 1

    def _print_upload_result(self, result: dict, no_cleanup: bool) -> None:
        """Print upload result in human-readable format"""
        print("✅ Document uploaded successfully!")
        print(f"   S3 URL: {result['s3_url']}")
        print(f"   S3 Key: {result['s3_key']}")
        print(f"   Bucket: {result['bucket']}")
        print(f"   Upload Time: {result['upload_timestamp']}")
        print(f"   File Size: {result['file_size']:,} bytes")

        # Retry information
        if "retry_count" in result and result["retry_count"] > 0:
            print(f"   Retry Attempts: {result['retry_count']}")

        if "retry_metrics" in result:
            metrics = result["retry_metrics"]
            print(f"   Total Attempts: {metrics['total_attempts']}")
            print(f"   Total Retry Time: {metrics['total_retry_time']:.2f} seconds")

        # Special features
        if result.get("resumed_from_checkpoint"):
            print(f"   📤 Resumed from: {result['resumed_from_checkpoint']}%")

        if result.get("circuit_recovered"):
            print(f"   🔄 Circuit breaker recovered")

        if result.get("token_refreshed"):
            print(f"   🔑 Authentication token refreshed")

        # Cleanup status
        if result.get("local_file_deleted", False):
            print(f"   🗑️  Local encrypted file deleted")
        elif no_cleanup:
            print(f"   💾 Local encrypted file preserved")
        elif "cleanup_warning" in result:
            print(f"   ⚠️  {result['cleanup_warning']}")

        print(f"\n📋 Next Steps:")
        print(f"   - Document is securely stored in S3")
        print(f"   - Original scanned file can be deleted")
        print(f"   - S3 URL can be used for document retrieval")

    def _handle_health(self, args) -> int:
        """Handle network health status command"""
        try:
            result = self.upload_service.get_network_health_score()

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_health(result)

            return 0

        except Exception as e:
            self._print_error("Failed to get network health status", e, args.json)
            return 1

    def _print_health(self, result: dict) -> None:
        """Print network health in human-readable format"""
        score = result.get("score", 0)
        success_rate = result.get("recent_success_rate", 0)
        avg_retry_count = result.get("average_retry_count", 0)
        circuit_status = result.get("circuit_breaker_status", "unknown")

        print("=== Network Health Status ===")

        # Health indicator
        if score >= 90:
            indicator = "✅"
            status = "EXCELLENT"
        elif score >= 75:
            indicator = "🟢"
            status = "GOOD"
        elif score >= 50:
            indicator = "🟡"
            status = "FAIR"
        else:
            indicator = "🔴"
            status = "POOR"

        print(f"{indicator} Network Health: {score}/100 ({status})")
        print(f"   Success Rate: {success_rate:.1%}")
        print(f"   Average Retries: {avg_retry_count:.1f}")
        print(f"   Circuit Breaker: {circuit_status.title()}")

        # Recommendations
        if score < 75:
            print(f"\n💡 Recommendations:")
            if success_rate < 0.9:
                print(f"   - Check network connectivity")
            if avg_retry_count > 1.5:
                print(f"   - Consider reducing upload frequency")
            if circuit_status == "open":
                print(f"   - Wait for circuit breaker cooldown")

    def _handle_stats(self, args) -> int:
        """Handle upload statistics command"""
        try:
            result = self.upload_service.get_upload_statistics()

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_stats(result)

            return 0

        except Exception as e:
            self._print_error("Failed to get upload statistics", e, args.json)
            return 1

    def _print_stats(self, result: dict) -> None:
        """Print upload statistics in human-readable format"""
        print("=== Upload Statistics ===")

        total_uploads = result.get("total_uploads", 0)
        successful_uploads = result.get("successful_uploads", 0)
        failed_uploads = result.get("failed_uploads", 0)
        success_rate = result.get("success_rate", 0)
        avg_retry_count = result.get("average_retry_count", 0)

        print(f"📊 Overall Statistics:")
        print(f"   Total Uploads: {total_uploads}")
        print(f"   Successful: {successful_uploads}")
        print(f"   Failed: {failed_uploads}")
        print(f"   Success Rate: {success_rate:.1%}")
        print(f"   Average Retries: {avg_retry_count:.2f}")

        # Circuit breaker info
        circuit_breaker = result.get("circuit_breaker", {})
        if circuit_breaker:
            print(f"\n🔌 Circuit Breaker:")
            print(f"   State: {circuit_breaker.get('state', 'unknown').title()}")
            print(f"   Failure Count: {circuit_breaker.get('failure_count', 0)}")
            print(f"   Threshold: {circuit_breaker.get('failure_threshold', 5)}")

        # Network health
        network_health = result.get("network_health", {})
        if network_health:
            print(f"\n🌐 Network Health: {network_health.get('score', 0)}/100")

    def _handle_config(self, args) -> int:
        """Handle S3 configuration command"""
        try:
            # Show basic config
            result = {
                "aws_region": self.upload_service.aws_region,
                "bucket_name": self.upload_service.bucket_name,
                "boto_config": {
                    "region": self.upload_service._boto_config.region_name,
                    "max_pool_connections": 10,
                    "retries_disabled": True,
                },
            }

            # Validate configuration if requested
            if args.validate:
                validation_result = self.upload_service.validate_s3_configuration()
                result["validation"] = validation_result

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_config(result, args.validate)

            return 0

        except Exception as e:
            self._print_error("Failed to get S3 configuration", e, args.json)
            return 1

    def _print_config(self, result: dict, validate: bool) -> None:
        """Print S3 configuration in human-readable format"""
        print("=== S3 Configuration ===")
        print(f"   AWS Region: {result['aws_region']}")
        print(f"   Bucket Name: {result['bucket_name']}")
        print(
            f"   Max Pool Connections: {result['boto_config']['max_pool_connections']}"
        )
        print(f"   Manual Retry Handling: {result['boto_config']['retries_disabled']}")

        if validate and "validation" in result:
            validation = result["validation"]
            print(f"\n🔍 Configuration Validation:")

            if validation.get("valid", False):
                print(f"   ✅ Configuration is valid")
                print(
                    f"   ✅ Bucket accessible: {validation.get('bucket_accessible', False)}"
                )
                print(
                    f"   ✅ Credentials valid: {validation.get('credentials_valid', False)}"
                )
            else:
                print(f"   ❌ Configuration has issues")
                if "error" in validation:
                    print(f"   Error: {validation['error']}")
                print(
                    f"   Bucket accessible: {validation.get('bucket_accessible', False)}"
                )
                print(
                    f"   Credentials valid: {validation.get('credentials_valid', False)}"
                )

        print(f"\n💡 Configuration Notes:")
        print(f"   - Retries are handled manually for better control")
        print(f"   - Circuit breaker protects against persistent failures")
        print(f"   - Upload paths follow: YYYY-MM-DD/branch/operator/pagare-epoch.enc")

    def _handle_estimate(self, args) -> int:
        """Handle upload time estimation command"""
        try:
            file_path = Path(args.file_path)
            if not file_path.exists():
                print(f"Error: File not found: {args.file_path}", file=sys.stderr)
                return 1

            file_size = file_path.stat().st_size
            estimated_time = self.upload_service.estimate_upload_time(file_size)

            result = {
                "file_path": str(file_path),
                "file_size_bytes": file_size,
                "estimated_time_seconds": estimated_time,
                "network_health_factor": "included",
            }

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_estimate(result)

            return 0

        except Exception as e:
            self._print_error("Failed to estimate upload time", e, args.json)
            return 1

    def _print_estimate(self, result: dict) -> None:
        """Print upload time estimate in human-readable format"""
        file_path = result["file_path"]
        file_size = result["file_size_bytes"]
        estimated_time = result["estimated_time_seconds"]

        print(f"⏱️  Upload Time Estimate")
        print(f"   File: {Path(file_path).name}")
        print(f"   Size: {file_size:,} bytes ({file_size / (1024 * 1024):.1f} MB)")
        print(f"   Estimated Time: {estimated_time:.1f} seconds")

        # Time categories
        if estimated_time > 60:
            minutes = estimated_time / 60
            print(f"   📅 Long upload (~{minutes:.1f} minutes)")
        elif estimated_time > 10:
            print(f"   ⏰ Medium upload")
        else:
            print(f"   ⚡ Quick upload")

        print(f"\n📊 Factors Affecting Speed:")
        print(f"   - Network health and connectivity")
        print(f"   - Current server load")
        print(f"   - File size and complexity")
        print(f"   - Retry logic overhead")

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

            # Add retry information for network errors
            if hasattr(error, "retry_count"):
                error_data["retry_count"] = error.retry_count
            if hasattr(error, "last_attempt_time"):
                error_data["last_attempt_time"] = error.last_attempt_time.isoformat()

            print(json.dumps(error_data, indent=2))
        else:
            print(f"❌ {message}: {error}", file=sys.stderr)

            # Show retry information for network errors
            if hasattr(error, "retry_count") and error.retry_count > 0:
                print(f"   Attempted {error.retry_count} retries", file=sys.stderr)


def main():
    """Main entry point for upload CLI"""
    cli = UploadCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
