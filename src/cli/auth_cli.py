#!/usr/bin/env python3
"""
Auth CLI Interface
Command-line interface for authentication and session management operations
"""

import argparse
import getpass
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.auth_service import (
    AuthenticationFailedError,
    AuthService,
    InvalidSessionError,
    SessionExpiredError,
)


class AuthCLI:
    """Command-line interface for authentication operations"""

    def __init__(self):
        self.auth_service = AuthService()
        self.parser = self._create_parser()
        self.session_file = Path.home() / ".scanner-session"

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command-line argument parser"""
        parser = argparse.ArgumentParser(
            prog="auth-cli",
            description="Authentication CLI Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  auth-cli login                                     # Interactive login
  auth-cli login admin                               # Login with username
  auth-cli login admin --password 1234              # Login with credentials
  auth-cli status                                    # Check session status
  auth-cli validate TOKEN                           # Validate session token
  auth-cli logout                                    # Logout current session
  auth-cli refresh                                   # Refresh session token
  auth-cli activity                                  # Show session activity
            """,
        )

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Login command
        login_parser = subparsers.add_parser("login", help="Login and create session")
        login_parser.add_argument(
            "username", nargs="?", help="Username (will prompt if not provided)"
        )
        login_parser.add_argument(
            "--password", "-p", help="Password (will prompt if not provided)"
        )
        login_parser.add_argument(
            "--save-session", action="store_true", help="Save session token to file"
        )
        login_parser.add_argument(
            "--json", action="store_true", help="Output result in JSON format"
        )

        # Status command
        status_parser = subparsers.add_parser(
            "status", help="Check current session status"
        )
        status_parser.add_argument(
            "--token", help="Session token to check (uses saved if not provided)"
        )
        status_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Validate command
        validate_parser = subparsers.add_parser(
            "validate", help="Validate session token"
        )
        validate_parser.add_argument(
            "token", nargs="?", help="Session token (uses saved if not provided)"
        )
        validate_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Logout command
        logout_parser = subparsers.add_parser(
            "logout", help="Logout and terminate session"
        )
        logout_parser.add_argument(
            "--token", help="Session token (uses saved if not provided)"
        )
        logout_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Refresh command
        refresh_parser = subparsers.add_parser("refresh", help="Refresh session token")
        refresh_parser.add_argument(
            "--token", help="Session token (uses saved if not provided)"
        )
        refresh_parser.add_argument(
            "--save-session", action="store_true", help="Save new session token to file"
        )
        refresh_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Activity command
        activity_parser = subparsers.add_parser(
            "activity", help="Show session activity history"
        )
        activity_parser.add_argument(
            "--token", help="Session token (uses saved if not provided)"
        )
        activity_parser.add_argument(
            "--limit", type=int, default=10, help="Number of activities to show"
        )
        activity_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Sessions command (admin)
        sessions_parser = subparsers.add_parser(
            "sessions", help="List all active sessions (admin only)"
        )
        sessions_parser.add_argument(
            "--json", action="store_true", help="Output in JSON format"
        )

        # Cleanup command (admin)
        cleanup_parser = subparsers.add_parser(
            "cleanup", help="Clean up expired sessions (admin only)"
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
                "login": self._handle_login,
                "status": self._handle_status,
                "validate": self._handle_validate,
                "logout": self._handle_logout,
                "refresh": self._handle_refresh,
                "activity": self._handle_activity,
                "sessions": self._handle_sessions,
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

    def _handle_login(self, args) -> int:
        """Handle login command"""
        try:
            # Get username
            if args.username:
                username = args.username
            else:
                username = input("Username: ")

            if not username:
                print("Error: Username is required", file=sys.stderr)
                return 1

            # Get password
            if args.password:
                password = args.password
            else:
                password = getpass.getpass("Password: ")

            if not password:
                print("Error: Password is required", file=sys.stderr)
                return 1

            print(f"🔐 Authenticating user: {username}")

            # Perform login
            result = self.auth_service.login(
                username=username,
                password=password,
                client_ip="127.0.0.1",  # Mock client IP
                user_agent="Scanner-CLI/1.0",
            )

            # Save session if requested
            if args.save_session:
                self._save_session_token(result["session_token"])
                result["session_saved"] = True

            if args.json:
                # Convert datetime to ISO string for JSON
                result_copy = result.copy()
                if isinstance(result_copy["expires_at"], datetime):
                    result_copy["expires_at"] = result_copy["expires_at"].isoformat()
                print(json.dumps(result_copy, indent=2))
            else:
                self._print_login_result(result, args.save_session)

            return 0

        except AuthenticationFailedError as e:
            self._print_auth_error(e, args.json)
            return 1
        except Exception as e:
            self._print_error("Login failed", e, args.json)
            return 1

    def _print_login_result(self, result: dict, save_session: bool) -> None:
        """Print login result in human-readable format"""
        print("✅ Login successful!")
        print(f"   Operator: {result['operator']} ({result['role']})")
        print(f"   Branch: {result['branch']}")
        print(f"   Session ID: {result['session_id']}")
        print(f"   Token: {result['session_token'][:32]}...")

        expires_at = result["expires_at"]
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)

        print(f"   Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}")

        # Calculate time until expiry
        time_left = expires_at - datetime.now()
        hours_left = time_left.total_seconds() / 3600
        print(f"   Valid for: {hours_left:.1f} hours")

        if save_session:
            print(f"   💾 Session token saved to {self.session_file}")

        print(f"\n🔑 Session Management:")
        print(f"   Use 'auth-cli status' to check session status")
        print(f"   Use 'auth-cli refresh' to extend session")
        print(f"   Use 'auth-cli logout' to terminate session")

    def _handle_status(self, args) -> int:
        """Handle session status command"""
        try:
            # Get session token
            token = args.token or self._load_session_token()
            if not token:
                if args.json:
                    print(
                        json.dumps(
                            {"error": True, "message": "No session token available"}
                        )
                    )
                else:
                    print(
                        "❌ No session token available. Please login first.",
                        file=sys.stderr,
                    )
                return 1

            # Check session status
            current_session = self.auth_service.get_current_session()

            if args.json:
                print(json.dumps(current_session, indent=2))
            else:
                self._print_session_status(current_session, token)

            return 0 if current_session.get("active", False) else 1

        except Exception as e:
            self._print_error("Failed to get session status", e, args.json)
            return 1

    def _print_session_status(self, status: dict, token: str) -> None:
        """Print session status in human-readable format"""
        if status.get("active", False):
            print("✅ Session is active")
            print(f"   Operator: {status.get('operator', 'Unknown')}")
            print(f"   Branch: {status.get('branch', 'Unknown')}")
            print(f"   Token: {token[:32]}...")
            print(f"   Created: {status.get('created_at', 'Unknown')}")
        else:
            print("❌ No active session")
            if self.session_file.exists():
                print("   💡 Saved session may have expired - try logging in again")

    def _handle_validate(self, args) -> int:
        """Handle session validation command"""
        try:
            # Get session token
            token = args.token or self._load_session_token()
            if not token:
                if args.json:
                    print(
                        json.dumps(
                            {"error": True, "message": "No session token provided"}
                        )
                    )
                else:
                    print("Error: No session token provided", file=sys.stderr)
                return 1

            # Validate session
            result = self.auth_service.validate_session(
                session_token=token, client_ip="127.0.0.1", user_agent="Scanner-CLI/1.0"
            )

            if args.json:
                # Convert datetime strings for JSON
                result_copy = result.copy()
                if "expires_at" in result_copy:
                    # Already in ISO format from service
                    pass
                print(json.dumps(result_copy, indent=2))
            else:
                self._print_validation_result(result, token)

            return 0 if result.get("valid", False) else 1

        except SessionExpiredError as e:
            self._print_session_error("Session expired", e, args.json)
            return 1
        except InvalidSessionError as e:
            self._print_session_error("Invalid session", e, args.json)
            return 1
        except Exception as e:
            self._print_error("Session validation failed", e, args.json)
            return 1

    def _print_validation_result(self, result: dict, token: str) -> None:
        """Print validation result in human-readable format"""
        if result.get("valid", False):
            print("✅ Session is valid")
            print(f"   Session ID: {result.get('session_id', 'Unknown')}")
            print(f"   Operator: {result.get('operator', 'Unknown')}")
            print(f"   Token: {token[:32]}...")

            expires_at_str = result.get("expires_at")
            if expires_at_str:
                expires_at = datetime.fromisoformat(expires_at_str)
                print(f"   Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}")

                time_left = result.get("time_until_expiry", 0)
                hours_left = time_left / 3600
                print(f"   Time Left: {hours_left:.1f} hours")
        else:
            print("❌ Session is invalid")

    def _handle_logout(self, args) -> int:
        """Handle logout command"""
        try:
            # Get session token
            token = args.token or self._load_session_token()
            if not token:
                if args.json:
                    print(
                        json.dumps(
                            {"error": True, "message": "No session token available"}
                        )
                    )
                else:
                    print("❌ No session token available", file=sys.stderr)
                return 1

            # Perform logout
            result = self.auth_service.logout(token)

            # Clean up saved session
            if self.session_file.exists():
                self.session_file.unlink()
                result["session_file_deleted"] = True

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_logout_result(result)

            return 0

        except Exception as e:
            self._print_error("Logout failed", e, args.json)
            return 1

    def _print_logout_result(self, result: dict) -> None:
        """Print logout result in human-readable format"""
        if result.get("success", False):
            print("✅ Logout successful")
            print(f"   Session terminated: {result.get('session_terminated', False)}")
            print(f"   Logout time: {result.get('logout_time', 'Unknown')}")

            if result.get("session_file_deleted", False):
                print(f"   💾 Session file removed")
        else:
            print("❌ Logout failed")
            print(f"   Error: {result.get('error', 'Unknown error')}")

    def _handle_refresh(self, args) -> int:
        """Handle session refresh command"""
        try:
            # Get session token
            token = args.token or self._load_session_token()
            if not token:
                if args.json:
                    print(
                        json.dumps(
                            {"error": True, "message": "No session token available"}
                        )
                    )
                else:
                    print("Error: No session token available", file=sys.stderr)
                return 1

            print("🔄 Refreshing session token...")

            # Refresh session
            result = self.auth_service.refresh_session(token)

            # Save new session if requested
            if args.save_session:
                self._save_session_token(result["new_session_token"])
                result["session_saved"] = True

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_refresh_result(result, args.save_session)

            return 0

        except SessionExpiredError as e:
            self._print_session_error("Cannot refresh expired session", e, args.json)
            return 1
        except InvalidSessionError as e:
            self._print_session_error("Cannot refresh invalid session", e, args.json)
            return 1
        except Exception as e:
            self._print_error("Session refresh failed", e, args.json)
            return 1

    def _print_refresh_result(self, result: dict, save_session: bool) -> None:
        """Print refresh result in human-readable format"""
        print("✅ Session refreshed successfully!")
        print(f"   New Token: {result['new_session_token'][:32]}...")

        expires_at_str = result.get("expires_at")
        if expires_at_str:
            if isinstance(expires_at_str, str):
                expires_at = datetime.fromisoformat(expires_at_str)
            else:
                expires_at = expires_at_str
            print(f"   New Expiry: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}")

        print(f"   Refresh Time: {result.get('refresh_time', 'Unknown')}")

        if save_session:
            print(f"   💾 New session token saved")

        print(f"\n🔐 Security Notes:")
        print(f"   - Old session token is now invalid")
        print(f"   - Use the new token for future operations")

    def _handle_activity(self, args) -> int:
        """Handle session activity command"""
        try:
            # Get session token
            token = args.token or self._load_session_token()
            if not token:
                if args.json:
                    print(
                        json.dumps(
                            {"error": True, "message": "No session token available"}
                        )
                    )
                else:
                    print("Error: No session token available", file=sys.stderr)
                return 1

            # Get session activity
            result = self.auth_service.get_session_activity(token)

            if "error" in result:
                if args.json:
                    print(json.dumps(result))
                else:
                    print(f"❌ {result['error']}", file=sys.stderr)
                return 1

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                self._print_activity(result, args.limit)

            return 0

        except Exception as e:
            self._print_error("Failed to get session activity", e, args.json)
            return 1

    def _print_activity(self, result: dict, limit: int) -> None:
        """Print session activity in human-readable format"""
        activities = result.get("activities", [])
        last_activity = result.get("last_activity_time", "Unknown")
        idle_duration = result.get("idle_duration", 0)

        print("=== Session Activity ===")
        print(f"   Last Activity: {last_activity}")
        print(f"   Idle Duration: {idle_duration / 60:.1f} minutes")

        if activities:
            print(f"\n📋 Recent Activities (showing {min(len(activities), limit)}):")
            for i, activity in enumerate(activities[:limit]):
                activity_type = activity.get("activity_type", "unknown")
                timestamp = activity.get("timestamp", "unknown")
                details = activity.get("details", {})

                print(f"   {i + 1}. {activity_type.upper()}")
                print(f"      Time: {timestamp}")
                if details:
                    for key, value in details.items():
                        print(f"      {key}: {value}")
                print()
        else:
            print(f"\n📋 No recent activities found")

    def _handle_sessions(self, args) -> int:
        """Handle list sessions command (admin only)"""
        try:
            # This would require admin privileges in a real implementation
            print("📋 Active Sessions (admin view):")
            print("   This feature requires admin implementation")

            # Mock session list
            mock_sessions = [
                {
                    "session_id": "sess_123456",
                    "operator": "admin",
                    "branch": "sucursal-centro",
                    "created_at": datetime.now().isoformat(),
                    "last_activity": (
                        datetime.now() - timedelta(minutes=5)
                    ).isoformat(),
                    "active": True,
                }
            ]

            if args.json:
                print(json.dumps({"sessions": mock_sessions}, indent=2))
            else:
                for session in mock_sessions:
                    print(f"   Session: {session['session_id']}")
                    print(f"     Operator: {session['operator']}")
                    print(f"     Branch: {session['branch']}")
                    print(f"     Active: {session['active']}")
                    print()

            return 0

        except Exception as e:
            self._print_error("Failed to list sessions", e, args.json)
            return 1

    def _handle_cleanup(self, args) -> int:
        """Handle session cleanup command (admin only)"""
        try:
            print("🧹 Cleaning up expired sessions...")

            result = self.auth_service.cleanup_expired_sessions()

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"✅ Cleanup completed")
                print(f"   Sessions cleaned: {result.get('sessions_cleaned', 0)}")
                print(f"   Cleanup time: {result.get('cleanup_time', 0):.3f} seconds")

            return 0

        except Exception as e:
            self._print_error("Session cleanup failed", e, args.json)
            return 1

    def _save_session_token(self, token: str) -> None:
        """Save session token to file"""
        try:
            with open(self.session_file, "w") as f:
                f.write(token)
            os.chmod(self.session_file, 0o600)  # Read/write for owner only
        except Exception as e:
            print(f"Warning: Could not save session token: {e}", file=sys.stderr)

    def _load_session_token(self) -> str:
        """Load session token from file"""
        try:
            if self.session_file.exists():
                with open(self.session_file, "r") as f:
                    return f.read().strip()
        except Exception:
            pass
        return ""

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

    def _print_auth_error(
        self, error: AuthenticationFailedError, json_output: bool = False
    ) -> None:
        """Print authentication error with specific handling"""
        if json_output:
            error_data = {
                "error": True,
                "message": "Authentication failed",
                "details": str(error),
                "error_code": error.error_code,
                "rate_limited": getattr(error, "rate_limited", False),
                "retry_after": getattr(error, "retry_after", 0),
                "timestamp": datetime.now().isoformat(),
            }
            print(json.dumps(error_data, indent=2))
        else:
            print(f"❌ Authentication failed: {error}", file=sys.stderr)
            if getattr(error, "rate_limited", False):
                retry_after = getattr(error, "retry_after", 0)
                print(
                    f"   Account temporarily locked. Retry after {retry_after} seconds.",
                    file=sys.stderr,
                )

    def _print_session_error(
        self, message: str, error: Exception, json_output: bool = False
    ) -> None:
        """Print session-specific error"""
        if json_output:
            error_data = {
                "error": True,
                "message": message,
                "details": str(error),
                "error_code": getattr(error, "error_code", "SESSION_ERROR"),
                "timestamp": datetime.now().isoformat(),
            }

            # Add session-specific fields
            if hasattr(error, "expired_at"):
                error_data["expired_at"] = error.expired_at.isoformat()
            if hasattr(error, "security_violation"):
                error_data["security_violation"] = error.security_violation

            print(json.dumps(error_data, indent=2))
        else:
            print(f"❌ {message}: {error}", file=sys.stderr)
            if hasattr(error, "expired_at"):
                print(f"   Session expired at: {error.expired_at}", file=sys.stderr)
            if hasattr(error, "security_violation"):
                print(
                    f"   Security violation: {error.security_violation}",
                    file=sys.stderr,
                )


def main():
    """Main entry point for auth CLI"""
    cli = AuthCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
