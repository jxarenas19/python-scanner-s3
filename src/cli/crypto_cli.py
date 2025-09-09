#!/usr/bin/env python3
"""
Crypto CLI Interface
Command-line interface for document encryption operations
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.crypto_service import (
    CryptoService,
    EncryptionError,
    FileNotFoundError,
    InsufficientDiskSpaceError,
    InvalidParametersError,
)


class CryptoCLI:
    """Command-line interface for cryptographic operations"""

    def __init__(self):
        self.crypto_service = CryptoService()
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command-line argument parser"""
        parser = argparse.ArgumentParser(
            prog="crypto-cli",
            description="Document Encryption CLI Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  crypto-cli encrypt document.tiff admin sucursal-centro    # Encrypt document
  crypto-cli encrypt document.tiff admin sucursal-centro --timestamp "2024-01-15T10:30:00"
  crypto-cli key-info admin sucursal-centro                # Get key derivation info
  crypto-cli verify document.tiff.enc                      # Verify encrypted file
  crypto-cli stats                                         # Show crypto statistics
  crypto-cli estimate document.tiff                        # Estimate encryption time
            """,
        )

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Encrypt command
        encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a document")
        encrypt_parser.add_argument(
            "file_path", help="Path to document file to encrypt"
        )
        encrypt_parser.add_argument("operator", help="Operator name")
        encrypt_parser.add_argument("branch", help="Branch name")
        encrypt_parser.add_argument("--timestamp", help="Custom timestamp (ISO format)")
        encrypt_parser.add_argument(
            "--output", "-o", help="Output directory for encrypted file"
        )
        encrypt_parser.add_argument(
            "--json", action="store_true", help="Output result in JSON format"
        )

        # Key info command
        keyinfo_parser = subparsers.add_parser(
            "key-info", help="Get key derivation information"
        )
        keyinfo_parser.add_argument("operator", help="Operator name")
        keyinfo_parser.add_argument("branch", help="Branch name")
        keyinfo_parser.add_argument("--timestamp", help="Custom timestamp (ISO format)")
        keyinfo_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Verify command
        verify_parser = subparsers.add_parser(
            "verify", help="Verify encrypted file integrity"
        )
        verify_parser.add_argument("encrypted_file", help="Path to encrypted file")
        verify_parser.add_argument(
            "--metadata", action="store_true", help="Show detailed metadata"
        )
        verify_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Statistics command
        stats_parser = subparsers.add_parser(
            "stats", help="Show cryptographic statistics"
        )
        stats_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Estimate command
        estimate_parser = subparsers.add_parser(
            "estimate", help="Estimate encryption time"
        )
        estimate_parser.add_argument("file_path", help="Path to file for estimation")
        estimate_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Cleanup command
        cleanup_parser = subparsers.add_parser(
            "cleanup", help="Clear ephemeral key cache"
        )
        cleanup_parser.add_argument(
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
                "encrypt": self._handle_encrypt,
                "key-info": self._handle_key_info,
                "verify": self._handle_verify,
                "stats": self._handle_stats,
                "estimate": self._handle_estimate,
                "cleanup": self._handle_cleanup,
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

    def _handle_encrypt(self, args) -> int:
        """Handle document encryption command"""
        try:
            # Validate file exists
            file_path = Path(args.file_path)
            if not file_path.exists():
                print(f"Error: File not found: {args.file_path}", file=sys.stderr)
                return 1

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

            print(f"🔐 Encrypting document: {file_path.name}")
            print(f"   Operator: {args.operator}")
            print(f"   Branch: {args.branch}")
            print(f"   Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

            # Perform encryption
            result = self.crypto_service.encrypt_document(
                file_path=str(file_path),
                operator=args.operator,
                timestamp=timestamp,
                branch=args.branch,
            )

            # Handle output directory
            if args.output:
                output_dir = Path(args.output)
                output_dir.mkdir(parents=True, exist_ok=True)

                # Move encrypted file to output directory
                encrypted_path = Path(result["encrypted_path"])
                new_path = output_dir / encrypted_path.name
                encrypted_path.rename(new_path)
                result["encrypted_path"] = str(new_path)

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_encrypt_result(result)

            return 0

        except FileNotFoundError as e:
            self._print_error("File not found", e, args.json)
            return 1
        except InvalidParametersError as e:
            self._print_error("Invalid parameters", e, args.json)
            return 1
        except EncryptionError as e:
            self._print_error("Encryption failed", e, args.json)
            return 1
        except InsufficientDiskSpaceError as e:
            self._print_error("Insufficient disk space", e, args.json)
            return 1
        except Exception as e:
            self._print_error("Unexpected error during encryption", e, args.json)
            return 1

    def _print_encrypt_result(self, result: dict) -> None:
        """Print encryption result in human-readable format"""
        print("✅ Document encrypted successfully!")
        print(f"   Encrypted File: {result['encrypted_path']}")
        print(f"   Algorithm: {result['algorithm']}")
        print(f"   Key Hash: {result['key_hash'][:16]}...")
        print(f"   File Size: {result['encrypted_size']:,} bytes")
        print(f"   Processing Time: {result['processing_time']:.3f} seconds")

        # Security reminder
        print("\n🔒 Security Notes:")
        print("   - Original file should be securely deleted after upload")
        print("   - Encrypted file contains no readable content")
        print("   - Key is derived from operator, branch, and timestamp")

    def _handle_key_info(self, args) -> int:
        """Handle key derivation information command"""
        try:
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

            result = self.crypto_service.get_key_derivation_info(
                operator=args.operator, branch=args.branch, timestamp=timestamp
            )

            if args.json:
                # Add timestamp for JSON output
                result_with_timestamp = result.copy()
                result_with_timestamp["timestamp"] = timestamp.isoformat()
                print(json.dumps(result_with_timestamp, indent=2))
            else:
                self._print_key_info(result, args.operator, args.branch, timestamp)

            return 0

        except Exception as e:
            self._print_error("Failed to get key derivation info", e, args.json)
            return 1

    def _print_key_info(
        self, result: dict, operator: str, branch: str, timestamp: datetime
    ) -> None:
        """Print key derivation info in human-readable format"""
        print("=== Key Derivation Information ===")
        print(f"   Operator: {operator}")
        print(f"   Branch: {branch}")
        print(f"   Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Key Hash: {result['key_hash']}")
        print(f"   Algorithm: {result['algorithm']}")
        print(f"   Iterations: {result['iterations']:,}")
        print(f"   Salt (Base64): {result['salt'][:32]}...")

        print("\n🔒 Security Information:")
        print("   - Key hash is used for identification only")
        print("   - Actual encryption key is never stored or transmitted")
        print("   - Salt is deterministically generated from inputs")
        print(f"   - PBKDF2 uses {result['iterations']:,} iterations for security")

    def _handle_verify(self, args) -> int:
        """Handle encrypted file verification command"""
        try:
            encrypted_file = Path(args.encrypted_file)
            if not encrypted_file.exists():
                print(
                    f"Error: Encrypted file not found: {args.encrypted_file}",
                    file=sys.stderr,
                )
                return 1

            # Verify file integrity
            is_valid = self.crypto_service.verify_encrypted_file(str(encrypted_file))

            result = {"valid": is_valid, "file_path": str(encrypted_file)}

            # Get metadata if requested and file is valid
            if args.metadata and is_valid:
                try:
                    metadata = self.crypto_service.get_encryption_metadata(
                        str(encrypted_file)
                    )
                    result["metadata"] = metadata
                except Exception as e:
                    result["metadata_error"] = str(e)

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_verify_result(result, args.metadata)

            return 0 if is_valid else 1

        except Exception as e:
            self._print_error("Failed to verify encrypted file", e, args.json)
            return 1

    def _print_verify_result(self, result: dict, show_metadata: bool) -> None:
        """Print verification result in human-readable format"""
        file_path = result["file_path"]
        is_valid = result["valid"]

        if is_valid:
            print(f"✅ Encrypted file is valid: {Path(file_path).name}")

            if show_metadata and "metadata" in result:
                metadata = result["metadata"]
                print(f"\n📊 File Metadata:")
                print(f"   Total Size: {metadata['encrypted_file_size']:,} bytes")
                print(f"   Content Size: {metadata['content_size']:,} bytes")
                print(f"   IV Size: {metadata['iv_size']} bytes")
                print(f"   Tag Size: {metadata['tag_size']} bytes")
                print(f"   Algorithm: {metadata['algorithm']}")
                print(f"   Created: {metadata['created_at']}")
            elif show_metadata and "metadata_error" in result:
                print(f"⚠️  Could not read metadata: {result['metadata_error']}")
        else:
            print(f"❌ Invalid encrypted file: {Path(file_path).name}")
            print("   File may be corrupted or not a valid encrypted document")

    def _handle_stats(self, args) -> int:
        """Handle cryptographic statistics command"""
        try:
            result = self.crypto_service.get_crypto_statistics()

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_stats(result)

            return 0

        except Exception as e:
            self._print_error("Failed to get crypto statistics", e, args.json)
            return 1

    def _print_stats(self, result: dict) -> None:
        """Print crypto statistics in human-readable format"""
        print("=== Cryptographic Statistics ===")
        print(f"   Encryption Algorithm: {result['algorithm']}")
        print(f"   Key Derivation: {result['key_derivation']}")
        print(f"   Key Size: {result['key_size_bits']} bits")
        print(f"   IV Size: {result['iv_size_bits']} bits")
        print(f"   Tag Size: {result['tag_size_bits']} bits")
        print(f"   PBKDF2 Iterations: {result['iterations']:,}")
        print(f"   Security Level: {result['security_level'].title()}")
        print(f"   Cache Entries: {result['cache_entries']}")

        print(f"\n🔐 Security Standards:")
        print(f"   - Uses industry-standard AES-256-GCM encryption")
        print(f"   - PBKDF2-SHA256 with {result['iterations']:,} iterations")
        print(f"   - 96-bit IV and 128-bit authentication tag")
        print(f"   - Keys are ephemeral (never stored persistently)")

    def _handle_estimate(self, args) -> int:
        """Handle encryption time estimation command"""
        try:
            file_path = Path(args.file_path)
            if not file_path.exists():
                print(f"Error: File not found: {args.file_path}", file=sys.stderr)
                return 1

            file_size = file_path.stat().st_size
            estimated_time = self.crypto_service.estimate_encryption_time(file_size)

            result = {
                "file_path": str(file_path),
                "file_size_bytes": file_size,
                "estimated_time_seconds": estimated_time,
            }

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_estimate(result)

            return 0

        except Exception as e:
            self._print_error("Failed to estimate encryption time", e, args.json)
            return 1

    def _print_estimate(self, result: dict) -> None:
        """Print encryption time estimate in human-readable format"""
        file_path = result["file_path"]
        file_size = result["file_size_bytes"]
        estimated_time = result["estimated_time_seconds"]

        print(f"⏱️  Encryption Time Estimate")
        print(f"   File: {Path(file_path).name}")
        print(f"   Size: {file_size:,} bytes ({file_size / (1024 * 1024):.1f} MB)")
        print(f"   Estimated Time: {estimated_time:.2f} seconds")

        if estimated_time > 5:
            print(f"   ⚠️  Large file - consider breaking into smaller chunks")
        elif estimated_time < 0.5:
            print(f"   ✅ Quick encryption expected")

    def _handle_cleanup(self, args) -> int:
        """Handle key cache cleanup command"""
        try:
            self.crypto_service.cleanup_key_cache()

            result = {
                "success": True,
                "message": "Key cache cleared successfully",
                "timestamp": datetime.now().isoformat(),
            }

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print("✅ Key cache cleared successfully")
                print("   All ephemeral keys have been removed from memory")

            return 0

        except Exception as e:
            self._print_error("Failed to cleanup key cache", e, args.json)
            return 1

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


def main():
    """Main entry point for crypto CLI"""
    cli = CryptoCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
