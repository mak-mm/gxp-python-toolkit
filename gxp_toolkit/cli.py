#!/usr/bin/env python3
"""
Command-line interface for GxP Python Toolkit.

Provides validation, reporting, and management tools for GxP compliance.
"""

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

import click
import pandas as pd  # type: ignore[import-untyped]
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

from . import __version__
from .access_control import authenticate, get_current_user, initialize_rbac
from .audit_trail import get_audit_storage as _get_audit_storage_async
from .config import StorageBackend, get_config, set_config

console = Console()


def get_audit_storage_sync() -> Any:
    """Synchronous wrapper for async get_audit_storage."""
    import asyncio

    async def _get() -> Any:
        return await _get_audit_storage_async()

    return asyncio.run(_get())


@click.group(invoke_without_command=True)
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """GxP Python Toolkit - Compliance tools for life sciences software."""
    if ctx.invoked_subcommand is None:
        console.print(
            Panel.fit(
                f"[bold blue]GxP Python Toolkit[/bold blue] v{__version__}\n"
                "[dim]Compliance tools for life sciences software[/dim]\n\n"
                "Use [bold]gxp --help[/bold] to see available commands.",
                border_style="blue",
            )
        )


@cli.group()
def config() -> None:
    """Manage GxP toolkit configuration."""
    pass


@config.command("show")
@click.option("--format", type=click.Choice(["table", "json", "yaml"]), default="table")
def config_show(format: str) -> None:
    """Display current configuration."""
    try:
        config = get_config()
        config_dict = config.to_dict()

        if format == "json":
            console.print_json(data=config_dict)
        elif format == "yaml":
            import yaml  # type: ignore[import-untyped]

            console.print(yaml.dump(config_dict, default_flow_style=False))
        else:
            # Table format
            table = Table(title="GxP Configuration", show_header=True)
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")
            table.add_column("Description", style="dim")

            # Group settings by category
            categories = {
                "General": ["application_name", "environment", "timezone"],
                "Audit Trail": [
                    "audit_enabled",
                    "audit_backend",
                    "audit_retention_days",
                ],
                "Security": [
                    "password_min_length",
                    "session_timeout_minutes",
                    "require_mfa",
                ],
                "Azure RBAC": [
                    "azure_tenant_id",
                    "azure_subscription_id",
                    "azure_resource_group",
                ],
                "Data Integrity": ["checksum_algorithm", "require_change_reason"],
                "Soft Delete": ["soft_delete_enabled", "cascade_delete_enabled"],
            }

            for category, settings in categories.items():
                table.add_row(f"[bold]{category}[/bold]", "", "")
                for setting in settings:
                    if setting in config_dict:
                        value = config_dict[setting]
                        if value is None:
                            value = "[dim]Not configured[/dim]"
                        elif isinstance(value, bool):
                            value = "✓" if value else "✗"
                        table.add_row(f"  {setting}", str(value), "")

            console.print(table)

    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set a configuration value."""
    try:
        config = get_config()

        # Convert value to appropriate type
        converted_value: Any = value
        if hasattr(config, key):
            current_value = getattr(config, key)
            if isinstance(current_value, bool):
                converted_value = value.lower() in ("true", "yes", "1", "on")
            elif isinstance(current_value, int):
                converted_value = int(value)
            elif isinstance(current_value, float):
                converted_value = float(value)

        setattr(config, key, converted_value)
        set_config(config)

        console.print(f"[green]✓[/green] Set {key} = {converted_value}")

    except AttributeError:
        console.print(f"[red]Error: Unknown configuration key '{key}'[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error setting configuration: {e}[/red]")
        sys.exit(1)


@config.command("validate")
def config_validate() -> None:
    """Validate current configuration."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Validating configuration...", total=None)

        try:
            config = get_config()

            # Validate settings
            issues = []
            warnings = []

            # Check audit retention
            if config.audit_retention_days < 2555:  # 7 years
                issues.append(
                    "Audit retention must be at least 7 years for GxP compliance"
                )

            # Check password policy
            if config.password_min_length < 12:
                warnings.append(
                    "Consider increasing password minimum length to 12+ characters"
                )

            # Check Azure configuration
            if config.audit_backend == "file" and config.environment == "production":
                warnings.append(
                    "File-based audit backend not recommended for production"
                )

            if not config.azure_tenant_id and config.environment == "production":
                warnings.append(
                    "Azure RBAC not configured - authentication may be limited"
                )

            progress.stop()

            if issues:
                console.print("[red]✗ Configuration validation failed:[/red]")
                for issue in issues:
                    console.print(f"  [red]• {issue}[/red]")
                sys.exit(1)
            else:
                console.print("[green]✓ Configuration is valid[/green]")

            if warnings:
                console.print("\n[yellow]⚠ Warnings:[/yellow]")
                for warning in warnings:
                    console.print(f"  [yellow]• {warning}[/yellow]")

        except Exception as e:
            progress.stop()
            console.print(f"[red]Error validating configuration: {e}[/red]")
            sys.exit(1)


@cli.group()
def audit() -> None:
    """Audit trail management and reporting."""
    pass


@audit.command("search")
@click.option("--user", help="Filter by user ID")
@click.option("--action", help="Filter by action")
@click.option("--resource-type", help="Filter by resource type")
@click.option("--start-date", type=click.DateTime(), help="Start date for search")
@click.option("--end-date", type=click.DateTime(), help="End date for search")
@click.option("--limit", type=int, default=100, help="Maximum results to return")
@click.option("--format", type=click.Choice(["table", "json", "csv"]), default="table")
def audit_search(
    user: Optional[str],
    action: Optional[str],
    resource_type: Optional[str],
    start_date: Optional[datetime],
    end_date: Optional[datetime],
    limit: int,
    format: str,
) -> None:
    """Search audit trail entries."""
    try:
        storage = get_audit_storage_sync()

        # Build filters
        filters: Dict[str, Any] = {}
        if user:
            filters["user_id"] = user
        if action:
            filters["action"] = action
        if resource_type:
            filters["resource_type"] = resource_type
        if start_date:
            filters["start_date"] = start_date
        if end_date:
            filters["end_date"] = end_date

        # Query entries
        entries = storage.query_entries(filters=filters, limit=limit)

        if not entries:
            console.print("[yellow]No audit entries found matching criteria[/yellow]")
            return

        if format == "json":
            # Convert entries to dict format
            data = [
                entry.dict() if hasattr(entry, "dict") else entry for entry in entries
            ]
            console.print_json(data=data)
        elif format == "csv":
            # Convert to CSV
            df = pd.DataFrame(
                [entry.dict() if hasattr(entry, "dict") else entry for entry in entries]
            )
            print(df.to_csv(index=False))
        else:
            # Table format
            table = Table(
                title=f"Audit Trail Entries (showing {len(entries)} of {limit})"
            )
            table.add_column("Timestamp", style="cyan")
            table.add_column("User", style="green")
            table.add_column("Action", style="yellow")
            table.add_column("Resource", style="blue")
            table.add_column("Result", style="magenta")

            for entry in entries:
                timestamp = (
                    entry.timestamp
                    if hasattr(entry, "timestamp")
                    else entry.get("timestamp", "")
                )
                user_id = (
                    entry.user_id
                    if hasattr(entry, "user_id")
                    else entry.get("user_id", "system")
                )
                action = (
                    entry.action
                    if hasattr(entry, "action")
                    else entry.get("action", "")
                )
                resource_type = (
                    entry.resource_type
                    if hasattr(entry, "resource_type")
                    else entry.get("resource_type", "")
                )
                resource_id = (
                    entry.resource_id
                    if hasattr(entry, "resource_id")
                    else entry.get("resource_id", "")
                )
                resource = f"{resource_type}:{resource_id}"
                result = (
                    entry.result
                    if hasattr(entry, "result")
                    else entry.get("result", "success")
                )

                # Format timestamp
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.fromisoformat(
                            timestamp.replace("Z", "+00:00")
                        )
                    except (ValueError, AttributeError):
                        pass
                if hasattr(timestamp, "strftime"):
                    timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

                # Color result
                if result == "success":
                    result = "[green]success[/green]"
                elif result == "failure":
                    result = "[red]failure[/red]"

                table.add_row(str(timestamp), user_id, action, resource, result)

            console.print(table)

    except Exception as e:
        console.print(f"[red]Error searching audit trail: {e}[/red]")
        sys.exit(1)


@audit.command("export")
@click.option(
    "--start-date", type=click.DateTime(), required=True, help="Start date for export"
)
@click.option(
    "--end-date", type=click.DateTime(), required=True, help="End date for export"
)
@click.option("--output", type=click.Path(), required=True, help="Output file path")
@click.option("--format", type=click.Choice(["json", "csv", "excel"]), default="csv")
def audit_export(
    start_date: datetime, end_date: datetime, output: str, format: str
) -> None:
    """Export audit trail for compliance reporting."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Exporting audit trail...", total=None)

        try:
            storage = get_audit_storage_sync()

            # Query all entries in date range
            entries = storage.query_entries(
                filters={"start_date": start_date, "end_date": end_date}
            )

            progress.update(
                task, description=f"Found {len(entries)} entries, exporting..."
            )

            # Convert to DataFrame
            data = [
                entry.dict() if hasattr(entry, "dict") else entry for entry in entries
            ]
            df = pd.DataFrame(data)

            # Export based on format
            output_path = Path(output)
            if format == "json":
                df.to_json(output_path, orient="records", date_format="iso", indent=2)
            elif format == "excel":
                df.to_excel(output_path, index=False, engine="openpyxl")
            else:  # csv
                df.to_csv(output_path, index=False)

            progress.stop()
            console.print(
                f"[green]✓ Exported {len(entries)} audit entries to "
                f"{output_path}[/green]"
            )

        except Exception as e:
            progress.stop()
            console.print(f"[red]Error exporting audit trail: {e}[/red]")
            sys.exit(1)


@audit.command("stats")
@click.option("--days", type=int, default=30, help="Number of days to analyze")
def audit_stats(days: int) -> None:
    """Display audit trail statistics."""
    try:
        storage = get_audit_storage_sync()
        start_date = datetime.utcnow() - timedelta(days=days)

        # Get entries
        entries = storage.query_entries(filters={"start_date": start_date})

        if not entries:
            console.print(
                f"[yellow]No audit entries found in the last {days} days[/yellow]"
            )
            return

        # Calculate statistics
        total_entries = len(entries)

        # Group by action
        action_counts: Dict[str, int] = {}
        user_counts: Dict[str, int] = {}
        resource_counts: Dict[str, int] = {}
        failure_count = 0

        for entry in entries:
            # Count actions
            action = (
                entry.action
                if hasattr(entry, "action")
                else entry.get("action", "unknown")
            )
            action_counts[action] = action_counts.get(action, 0) + 1

            # Count users
            user = (
                entry.user_id
                if hasattr(entry, "user_id")
                else entry.get("user_id", "unknown")
            )
            user_counts[user] = user_counts.get(user, 0) + 1

            # Count resources
            resource = (
                entry.resource_type
                if hasattr(entry, "resource_type")
                else entry.get("resource_type", "unknown")
            )
            resource_counts[resource] = resource_counts.get(resource, 0) + 1

            # Count failures
            result = (
                entry.result
                if hasattr(entry, "result")
                else entry.get("result", "success")
            )
            if result == "failure":
                failure_count += 1

        # Display statistics
        console.print(
            Panel.fit(
                f"[bold]Audit Trail Statistics[/bold]\n"
                f"Last {days} days\n\n"
                f"Total entries: [cyan]{total_entries:,}[/cyan]\n"
                f"Unique users: [green]{len(user_counts)}[/green]\n"
                f"Unique actions: [yellow]{len(action_counts)}[/yellow]\n"
                f"Failed operations: [red]{failure_count}[/red] "
                f"({failure_count/total_entries*100:.1f}%)",
                border_style="blue",
            )
        )

        # Top actions table
        table = Table(title="Top Actions")
        table.add_column("Action", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Percentage", style="yellow")

        sorted_actions = sorted(
            action_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
        for action, count in sorted_actions:
            percentage = count / total_entries * 100
            table.add_row(action, str(count), f"{percentage:.1f}%")

        console.print(table)

        # Top users table
        console.print()
        table = Table(title="Most Active Users")
        table.add_column("User", style="cyan")
        table.add_column("Actions", style="green")

        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for user, count in sorted_users:
            table.add_row(user, str(count))

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error calculating statistics: {e}[/red]")
        sys.exit(1)


@cli.group()
def auth() -> None:
    """Authentication and access control management."""
    pass


@auth.command("login")
@click.option(
    "--method",
    type=click.Choice(["cli", "managed-identity", "service-principal"]),
    default="cli",
    help="Authentication method",
)
def auth_login(method: str) -> None:
    """Authenticate with Azure RBAC."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Authenticating...", total=None)

        try:
            # Initialize RBAC if needed
            initialize_rbac()

            # Authenticate
            user = authenticate()

            progress.stop()

            # Display user info
            console.print(
                Panel.fit(
                    f"[bold green]✓ Successfully authenticated[/bold green]\n\n"
                    f"User: [cyan]{user.name}[/cyan]\n"
                    f"Email: [cyan]{user.email}[/cyan]\n"
                    f"ID: [dim]{user.id}[/dim]\n"
                    f"Method: [yellow]{user.authentication_method.value}[/yellow]\n"
                    f"Roles: {', '.join(user.roles)}\n"
                    f"Permissions: [dim]{len(user.permissions)} granted[/dim]",
                    title="Authentication Successful",
                    border_style="green",
                )
            )

        except Exception as e:
            progress.stop()
            console.print(f"[red]Authentication failed: {e}[/red]")
            sys.exit(1)


@auth.command("whoami")
def auth_whoami() -> None:
    """Display current user information."""
    try:
        user = get_current_user()

        if not user:
            console.print(
                "[yellow]Not authenticated. Use 'gxp auth login' to "
                "authenticate.[/yellow]"
            )
            return

        # Create permissions tree
        tree = Tree("[bold]Current User[/bold]")
        tree.add(f"Name: [cyan]{user.name}[/cyan]")
        tree.add(f"Email: [cyan]{user.email}[/cyan]")
        tree.add(f"ID: [dim]{user.id}[/dim]")
        tree.add(f"Auth Method: [yellow]{user.authentication_method.value}[/yellow]")

        # Add roles
        roles_branch = tree.add("Roles")
        for role in user.roles:
            roles_branch.add(f"[green]{role}[/green]")

        # Add permissions
        perms_branch = tree.add(f"Permissions ({len(user.permissions)})")
        for perm in sorted(user.permissions, key=lambda p: p.value):
            perms_branch.add(f"[blue]{perm.value}[/blue]")

        console.print(tree)

        # Check token expiry
        if user.token_expires_at:
            time_left = user.token_expires_at - datetime.utcnow()
            if time_left.total_seconds() > 0:
                hours = int(time_left.total_seconds() // 3600)
                minutes = int((time_left.total_seconds() % 3600) // 60)
                console.print(f"\n[dim]Token expires in {hours}h {minutes}m[/dim]")
            else:
                console.print("\n[red]Token has expired - please re-authenticate[/red]")

    except Exception as e:
        console.print(f"[red]Error getting user information: {e}[/red]")
        sys.exit(1)


@cli.group()
def validate() -> None:
    """Data validation and integrity checks."""
    pass


@validate.command("database")
@click.option(
    "--connection-string", envvar="GXP_DATABASE_URL", help="Database connection string"
)
@click.option(
    "--check-soft-deletes", is_flag=True, help="Validate soft delete integrity"
)
@click.option(
    "--check-audit-trail", is_flag=True, help="Validate audit trail integrity"
)
def validate_database(
    connection_string: Optional[str], check_soft_deletes: bool, check_audit_trail: bool
) -> None:
    """Validate database integrity and compliance."""
    if not connection_string:
        console.print("[red]Error: Database connection string required[/red]")
        console.print(
            "Set GXP_DATABASE_URL environment variable or use --connection-string"
        )
        sys.exit(1)

    issues = []
    warnings = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Check soft deletes
        if check_soft_deletes:
            task = progress.add_task("Checking soft delete integrity...", total=None)
            try:
                from sqlalchemy import create_engine, inspect, text

                engine = create_engine(connection_string)
                inspector = inspect(engine)

                # Check for tables with soft delete columns
                soft_delete_tables = []
                for table_name in inspector.get_table_names():
                    columns = [col["name"] for col in inspector.get_columns(table_name)]
                    if "deleted_at" in columns:
                        soft_delete_tables.append(table_name)

                # Validate each table
                for table in soft_delete_tables:
                    with engine.connect() as conn:
                        # Check for orphaned soft deletes
                        result = conn.execute(
                            text(
                                f"SELECT COUNT(*) FROM {table} WHERE "  # nosec B608
                                f"deleted_at IS NOT NULL AND deleted_reason IS NULL"
                            )
                        )
                        orphaned = result.scalar()
                        if orphaned is not None and orphaned > 0:
                            issues.append(
                                f"Table '{table}' has {orphaned} soft-deleted "
                                f"records without deletion reason"
                            )

                progress.update(
                    task, description=f"Checked {len(soft_delete_tables)} tables"
                )

            except Exception as e:
                issues.append(f"Failed to check soft deletes: {e}")
            finally:
                progress.remove_task(task)

        # Check audit trail
        if check_audit_trail:
            task = progress.add_task("Checking audit trail integrity...", total=None)
            try:
                storage = get_audit_storage_sync()

                # Get recent entries
                recent_entries = storage.query_entries(
                    filters={"start_date": datetime.utcnow() - timedelta(days=1)},
                    limit=1000,
                )

                # Check for gaps in sequence
                if hasattr(storage, "check_integrity"):
                    integrity_issues = storage.check_integrity()
                    if integrity_issues:
                        issues.extend(integrity_issues)

                # Check for missing checksums
                missing_checksums = 0
                for entry in recent_entries:
                    if not hasattr(entry, "checksum") or not entry.checksum:
                        missing_checksums += 1

                if missing_checksums > 0:
                    warnings.append(
                        f"{missing_checksums} audit entries missing checksums"
                    )

                progress.update(
                    task, description=f"Checked {len(recent_entries)} audit entries"
                )

            except Exception as e:
                issues.append(f"Failed to check audit trail: {e}")
            finally:
                progress.remove_task(task)

    # Display results
    if issues:
        console.print("\n[red]✗ Validation failed with the following issues:[/red]")
        for issue in issues:
            console.print(f"  [red]• {issue}[/red]")
    else:
        console.print("\n[green]✓ All validation checks passed[/green]")

    if warnings:
        console.print("\n[yellow]⚠ Warnings:[/yellow]")
        for warning in warnings:
            console.print(f"  [yellow]• {warning}[/yellow]")

    # Exit with error if issues found
    if issues:
        sys.exit(1)


@cli.command()
def doctor() -> None:
    """Run diagnostic checks on GxP toolkit installation."""
    console.print("[bold]Running GxP Toolkit diagnostics...[/bold]\n")

    checks_passed = 0
    checks_failed = 0

    # Check 1: Configuration
    try:
        config = get_config()
        console.print("[green]✓[/green] Configuration loaded successfully")
        checks_passed += 1
    except Exception as e:
        console.print(f"[red]✗[/red] Configuration error: {e}")
        checks_failed += 1

    # Check 2: Azure authentication
    try:
        from azure.identity import DefaultAzureCredential

        DefaultAzureCredential()
        console.print("[green]✓[/green] Azure authentication available")
        checks_passed += 1
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Azure authentication not configured: {e}")
        checks_failed += 1

    # Check 3: Database connectivity (if configured)
    db_url = os.getenv("GXP_DATABASE_URL")
    if db_url:
        try:
            from sqlalchemy import create_engine, text

            engine = create_engine(db_url)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            console.print("[green]✓[/green] Database connection successful")
            checks_passed += 1
        except Exception as e:
            console.print(f"[red]✗[/red] Database connection failed: {e}")
            checks_failed += 1
    else:
        console.print(
            "[yellow]⚠[/yellow] No database configured (GXP_DATABASE_URL not set)"
        )

    # Check 4: Audit trail storage
    try:
        get_audit_storage_sync()
        console.print(
            f"[green]✓[/green] Audit trail storage initialized "
            f"({config.audit_storage_backend.value})"
        )
        checks_passed += 1
    except Exception as e:
        console.print(f"[red]✗[/red] Audit trail storage error: {e}")
        checks_failed += 1

    # Check 5: Required directories
    if config.audit_storage_backend == StorageBackend.FILE:
        audit_path = config.audit_file_path or "./audit_logs"
        audit_dir = Path(audit_path).parent
        if audit_dir.exists() and audit_dir.is_dir():
            console.print(f"[green]✓[/green] Audit directory exists: {audit_dir}")
            checks_passed += 1
        else:
            console.print(f"[red]✗[/red] Audit directory missing: {audit_dir}")
            checks_failed += 1

    # Summary
    console.print("\n[bold]Summary:[/bold]")
    console.print(f"  Checks passed: [green]{checks_passed}[/green]")
    console.print(f"  Checks failed: [red]{checks_failed}[/red]")

    if checks_failed == 0:
        console.print("\n[green]✓ All systems operational[/green]")
    else:
        console.print("\n[yellow]⚠ Some issues detected - review output above[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    cli()
