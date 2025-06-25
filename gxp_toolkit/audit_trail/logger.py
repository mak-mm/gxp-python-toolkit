"""
Core audit logger implementation.

Provides the main AuditLogger class for recording audit trail entries
in compliance with 21 CFR Part 11.
"""

import asyncio
import inspect
import uuid
from contextvars import ContextVar
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from ..config import get_config
from .models import AuditAction, AuditEntry, AuditQuery, AuditReport
from .storage import AuditStorage, get_audit_storage

# Context variables for audit context
current_user: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "current_user", default=None
)
current_session: ContextVar[Optional[str]] = ContextVar("current_session", default=None)
current_request: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "current_request", default=None
)


class AuditLogger:
    """Main audit logger for GxP compliance.

    This class provides the core functionality for audit trail creation and management
    in compliance with FDA 21 CFR Part 11 and EU Annex 11 requirements. It handles
    automatic capture of user actions, system events, and data changes with proper
    context and immutable storage.

    The logger supports both synchronous and asynchronous operations, batch processing
    for performance, and multiple storage backends for flexibility.

    Attributes:
        storage (AuditStorage): The storage backend for audit entries.
        application_name (str): Name of the application using the logger.
        batch_mode (bool): Whether to use batch processing for performance.
        batch_size (int): Number of entries to batch before flushing.
        flush_interval (float): Time interval in seconds for automatic flushing.

    Example:
        Basic usage with default configuration:

        >>> from gxp_toolkit import AuditLogger
        >>> audit = AuditLogger()
        >>>
        >>> @audit.log_activity("USER_LOGIN")
        >>> def login(username: str, password: str):
        ...     # Your login logic here
        ...     return {"status": "success", "user": username}

        Manual logging:

        >>> audit.log_event(
        ...     action="DATA_EXPORT",
        ...     user="john.doe",
        ...     details={"format": "csv", "records": 1000}
        ... )

        Batch context for performance:

        >>> with audit.batch_context() as batch:
        ...     for item in large_dataset:
        ...         process_item(item)
        ...         batch.add_detail(f"Processed {item.id}")

    Note:
        All audit entries are immutable once stored and include cryptographic
        checksums for integrity verification. The logger automatically captures
        user context, timestamps, and system information.
    """

    def __init__(
        self,
        storage: Optional[AuditStorage] = None,
        application_name: Optional[str] = None,
        batch_mode: bool = True,
        batch_size: int = 100,
        flush_interval: float = 5.0,
    ):
        """Initialize the audit logger with configuration options.

        Args:
            storage: Storage backend for audit entries. If None, uses the default
                storage configured in GxPConfig.
            application_name: Name of the application using this logger. Used for
                categorizing audit entries. If None, attempts to derive from the
                calling module.
            batch_mode: Whether to use batch processing for better performance.
                When True, entries are collected and flushed in batches.
            batch_size: Maximum number of entries to collect before automatic
                flushing. Only used when batch_mode is True.
            flush_interval: Time in seconds between automatic flushes. Only used
                when batch_mode is True.

        Raises:
            AuditError: If the storage backend cannot be initialized.
            ValueError: If batch_size is less than 1 or flush_interval is negative.

        Example:
            Custom configuration:

            >>> storage = PostgreSQLAuditStorage("postgresql://...")
            >>> audit = AuditLogger(
            ...     storage=storage,
            ...     application_name="MyApp",
            ...     batch_size=50,
            ...     flush_interval=10.0
            ... )
        """
        self.storage = storage
        self.config = get_config()
        self.application_name = application_name or self.config.application_name
        self.batch_mode = batch_mode and self.config.audit_async_writes
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        # Batch processing
        self._batch: List[AuditEntry] = []
        self._batch_lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task[None]] = None

        # Initialize storage if needed
        if self.storage is None:
            asyncio.create_task(self._init_storage())

    async def _init_storage(self) -> None:
        """Initialize default storage backend."""
        self.storage = await get_audit_storage(
            backend=self.config.audit_storage_backend.value,
            connection_string=getattr(self.config, "database_url", None),
            storage_path=getattr(self.config, "audit_file_path", "./audit_logs"),
        )

    async def _ensure_storage(self) -> None:
        """Ensure storage is initialized."""
        if self.storage is None:
            await self._init_storage()

    def set_context(
        self,
        user: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        request: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Set audit context for current execution.

        Args:
            user: User information (id, name, roles)
            session_id: Session identifier
            request: Request information (ip, user_agent, etc.)
        """
        if user is not None:
            current_user.set(user)
        if session_id is not None:
            current_session.set(session_id)
        if request is not None:
            current_request.set(request)

    async def log_activity(
        self,
        action: Union[str, AuditAction],
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        reference_id: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        user_override: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Log an audit trail entry.

        Args:
            action: Action performed
            entity_type: Type of entity affected
            entity_id: ID of entity affected
            old_values: Previous values (for updates)
            new_values: New values (for updates)
            reason: Reason for the action
            reference_id: Reference to external system
            success: Whether action succeeded
            error_message: Error if action failed
            details: Additional context
            user_override: Override context user

        Returns:
            ID of the audit entry
        """
        await self._ensure_storage()

        # Get context
        user = user_override or current_user.get()
        session_id = current_session.get()
        request = current_request.get() or {}

        # Validate user context
        if not user:
            raise ValueError("User context is required for audit logging")

        # Get caller information
        frame = inspect.currentframe()
        caller_frame = frame.f_back if frame else None
        module = (
            caller_frame.f_globals.get("__name__", "unknown")
            if caller_frame
            else "unknown"
        )
        function = caller_frame.f_code.co_name if caller_frame else "unknown"

        # Create audit entry
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            local_timestamp=None,  # Will be set by storage if needed
            user_id=user.get("id", "unknown"),
            user_name=user.get("name"),
            user_roles=user.get("roles", []),
            action=action if isinstance(action, AuditAction) else AuditAction(action),
            entity_type=entity_type,
            entity_id=entity_id,
            old_values=old_values,
            new_values=new_values,
            reason=reason,
            reference_id=reference_id,
            application=self.application_name,
            module=module,
            function=function,
            ip_address=request.get("ip_address"),
            user_agent=request.get("user_agent"),
            session_id=session_id,
            details=details,
            success=success,
            error_message=error_message,
            checksum=None,  # Will be calculated by entry
        )

        # Add checksum
        entry.checksum = entry.calculate_checksum(self.config.checksum_algorithm.value)

        # Store entry
        if self.batch_mode:
            await self._add_to_batch(entry)
        else:
            if self.storage:
                await self.storage.store(entry)

        return entry.id

    async def _add_to_batch(self, entry: AuditEntry) -> None:
        """Add entry to batch for later processing."""
        async with self._batch_lock:
            self._batch.append(entry)

            # Flush if batch is full
            if len(self._batch) >= self.batch_size:
                await self._flush_batch()
            else:
                # Schedule flush if not already scheduled
                if self._flush_task is None or self._flush_task.done():
                    self._flush_task = asyncio.create_task(self._scheduled_flush())

    async def _scheduled_flush(self) -> None:
        """Flush batch after interval."""
        await asyncio.sleep(self.flush_interval)
        await self._flush_batch()

    async def _flush_batch(self) -> None:
        """Flush pending audit entries."""
        async with self._batch_lock:
            if self._batch and self.storage:
                await self.storage.store_batch(self._batch)
                self._batch = []

    async def flush(self) -> None:
        """Manually flush pending entries."""
        await self._flush_batch()

    async def query(self, query: AuditQuery) -> List[AuditEntry]:
        """
        Query audit entries.

        Args:
            query: Query parameters

        Returns:
            List of matching entries
        """
        await self._ensure_storage()
        if self.storage is None:  # nosec B101
            raise RuntimeError("Audit storage not available")
        return await self.storage.query(query)

    async def get_user_activities(
        self,
        user_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """
        Get activities for a specific user.

        Args:
            user_id: User to query
            start_date: Optional start date
            end_date: Optional end date
            limit: Maximum results

        Returns:
            List of user's activities
        """
        query = AuditQuery(
            user_ids=[user_id],
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            user_roles=None,
            actions=None,
            entity_types=None,
            entity_ids=None,
            success_only=False,
            failures_only=False,
            search_text=None,
            offset=0,
            sort_by="timestamp",
            sort_desc=True,
        )

        return await self.query(query)

    async def get_entity_history(
        self,
        entity_type: str,
        entity_id: str,
        include_related: bool = False,
    ) -> List[AuditEntry]:
        """
        Get complete history for an entity.

        Args:
            entity_type: Type of entity
            entity_id: Entity identifier
            include_related: Include related entity actions

        Returns:
            List of audit entries for the entity
        """
        query = AuditQuery(
            entity_types=[entity_type],
            entity_ids=[entity_id],
            sort_by="timestamp",
            sort_desc=False,  # Chronological order
            limit=1000,  # Reasonable limit for entity history
            start_date=None,
            end_date=None,
            user_ids=None,
            user_roles=None,
            actions=None,
            success_only=False,
            failures_only=False,
            search_text=None,
            offset=0,
        )

        entries = await self.query(query)

        if include_related:
            # Look for references in details
            related_entries = []
            for entry in entries:
                if entry.details and "related_entities" in entry.details:
                    for related in entry.details["related_entities"]:
                        related_query = AuditQuery(
                            entity_types=[related["type"]],
                            entity_ids=[related["id"]],
                            start_date=None,
                            end_date=None,
                            user_ids=None,
                            user_roles=None,
                            actions=None,
                            success_only=False,
                            failures_only=False,
                            search_text=None,
                            limit=100,
                            offset=0,
                            sort_by="timestamp",
                            sort_desc=True,
                        )
                        related_entries.extend(await self.query(related_query))

            entries.extend(related_entries)
            # Sort by timestamp
            entries.sort(key=lambda e: e.timestamp)

        return entries

    async def get_failed_actions(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        action_types: Optional[List[AuditAction]] = None,
    ) -> List[AuditEntry]:
        """
        Get failed actions for investigation.

        Args:
            start_date: Optional start date
            end_date: Optional end date
            action_types: Optional action filter

        Returns:
            List of failed actions
        """
        query = AuditQuery(
            start_date=start_date,
            end_date=end_date,
            actions=action_types,
            failures_only=True,
            sort_by="timestamp",
            sort_desc=True,
            user_ids=None,
            user_roles=None,
            entity_types=None,
            entity_ids=None,
            success_only=False,
            search_text=None,
            limit=100,
            offset=0,
        )

        return await self.query(query)

    async def generate_report(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None,
        generated_by: Optional[str] = None,
    ) -> AuditReport:
        """
        Generate audit report for compliance.

        Args:
            start_date: Report start date
            end_date: Report end date
            filters: Optional filters
            generated_by: User generating report

        Returns:
            Audit report
        """
        await self._ensure_storage()
        if self.storage is None:  # nosec B101
            raise RuntimeError("Audit storage not available")

        report = await self.storage.generate_report(
            start_date=start_date,
            end_date=end_date,
            filters=filters,
        )

        # Update generated_by if provided
        if generated_by:
            report.generated_by = generated_by

        # Log report generation
        await self.log_activity(
            action="REPORT_GENERATED",
            entity_type="AuditReport",
            entity_id=report.report_id,
            details={
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "filters": filters,
                "total_entries": report.total_entries,
            },
        )

        return report

    async def verify_integrity(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Verify integrity of audit entries.

        Args:
            start_date: Optional start date
            end_date: Optional end date

        Returns:
            Integrity verification results
        """
        await self._ensure_storage()
        if self.storage is None:  # nosec B101
            raise RuntimeError("Audit storage not available")

        results = await self.storage.verify_integrity(
            start_date=start_date,
            end_date=end_date,
        )

        # Log integrity check
        await self.log_activity(
            action="INTEGRITY_CHECK",
            details={
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None,
                "total_checked": results["total_checked"],
                "valid": results["valid"],
                "invalid": results["invalid"],
            },
            success=results["invalid"] == 0,
            error_message=(
                f"Found {results['invalid']} invalid entries"
                if results["invalid"] > 0
                else None
            ),
        )

        return results

    async def archive_old_entries(
        self,
        cutoff_date: datetime,
        archive_location: str,
    ) -> int:
        """
        Archive old audit entries.

        Args:
            cutoff_date: Archive entries before this date
            archive_location: Where to store archives

        Returns:
            Number of entries archived
        """
        await self._ensure_storage()
        if self.storage is None:  # nosec B101
            raise RuntimeError("Audit storage not available")

        # Archive entries
        archived_count = await self.storage.archive_old_entries(
            cutoff_date=cutoff_date,
            archive_location=archive_location,
        )

        # Log archival
        await self.log_activity(
            action="ARCHIVE_CREATED",
            details={
                "cutoff_date": cutoff_date.isoformat(),
                "archive_location": archive_location,
                "entries_archived": archived_count,
            },
        )

        return archived_count

    async def close(self) -> None:
        """Clean up resources and pending tasks."""
        # Flush any pending batches
        await self.flush()

        # Cancel any pending flush task
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass


# Global audit logger instance
_global_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _global_logger

    if _global_logger is None:
        _global_logger = AuditLogger()

    return _global_logger


def set_audit_logger(logger: AuditLogger) -> None:
    """Set the global audit logger instance."""
    global _global_logger
    _global_logger = logger
