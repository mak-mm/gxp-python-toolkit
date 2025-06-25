"""
Storage backends for audit trail data.

Provides abstract interface and implementations for various storage backends
ensuring immutability and compliance with 21 CFR Part 11.
"""

import asyncio
import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Index,
    String,
    Text,
    and_,
    asc,
    create_engine,
    desc,
    or_,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .models import AuditEntry, AuditQuery, AuditReport

Base = declarative_base()


class AuditEntryDB(Base):  # type: ignore[valid-type,misc]
    """SQLAlchemy model for audit entries."""

    __tablename__ = "audit_trail"

    # Primary key
    id = Column(String(50), primary_key=True)

    # Timestamps
    timestamp = Column(DateTime, nullable=False, index=True)
    local_timestamp = Column(DateTime, nullable=True)

    # User information
    user_id = Column(String(100), nullable=False, index=True)
    user_name = Column(String(200), nullable=True)
    user_roles = Column(JSON, nullable=True)

    # Action information
    action = Column(String(50), nullable=False, index=True)
    entity_type = Column(String(100), nullable=True, index=True)
    entity_id = Column(String(100), nullable=True, index=True)

    # Changes
    old_values = Column(JSON, nullable=True)
    new_values = Column(JSON, nullable=True)

    # Context
    reason = Column(Text, nullable=True)
    reference_id = Column(String(100), nullable=True)
    application = Column(String(100), nullable=False)
    module = Column(String(100), nullable=True)
    function = Column(String(200), nullable=True)

    # Network context
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)
    session_id = Column(String(100), nullable=True)

    # Additional details
    details = Column(JSON, nullable=True)

    # Result
    success = Column(Boolean, nullable=False, default=True)
    error_message = Column(Text, nullable=True)

    # Integrity
    checksum = Column(String(128), nullable=False)

    # Indexes for common queries
    __table_args__ = (
        Index("idx_audit_timestamp_action", timestamp, action),
        Index("idx_audit_entity", entity_type, entity_id),
        Index("idx_audit_user_timestamp", user_id, timestamp),
    )


class AuditStorage(ABC):
    """Abstract base class for audit trail storage backends."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        pass

    @abstractmethod
    async def store(self, entry: AuditEntry) -> None:
        """
        Store an audit entry.

        Args:
            entry: Audit entry to store

        Raises:
            StorageError: If storage fails
        """
        pass

    @abstractmethod
    async def store_batch(self, entries: List[AuditEntry]) -> None:
        """
        Store multiple audit entries in a batch.

        Args:
            entries: List of audit entries to store

        Raises:
            StorageError: If storage fails
        """
        pass

    @abstractmethod
    async def query(self, query: AuditQuery) -> List[AuditEntry]:
        """
        Query audit entries.

        Args:
            query: Query parameters

        Returns:
            List of matching audit entries
        """
        pass

    @abstractmethod
    async def get_by_id(self, entry_id: str) -> Optional[AuditEntry]:
        """
        Get a specific audit entry by ID.

        Args:
            entry_id: ID of the entry

        Returns:
            Audit entry or None if not found
        """
        pass

    @abstractmethod
    async def generate_report(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None,
    ) -> AuditReport:
        """
        Generate an audit report for a time period.

        Args:
            start_date: Start of report period
            end_date: End of report period
            filters: Optional additional filters

        Returns:
            Audit report with statistics
        """
        pass

    @abstractmethod
    async def verify_integrity(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Verify integrity of stored audit entries.

        Args:
            start_date: Optional start date
            end_date: Optional end date

        Returns:
            Integrity verification results
        """
        pass

    @abstractmethod
    async def archive_old_entries(
        self, cutoff_date: datetime, archive_location: str
    ) -> int:
        """
        Archive old audit entries.

        Args:
            cutoff_date: Archive entries before this date
            archive_location: Where to store archived entries

        Returns:
            Number of entries archived
        """
        pass


class SQLAuditStorage(AuditStorage):
    """SQL database storage backend for audit trails."""

    def __init__(self, connection_string: str):
        """
        Initialize SQL audit storage.

        Args:
            connection_string: Database connection string
        """
        self.connection_string = connection_string
        self.engine: Optional[Engine] = None
        self.SessionLocal: Optional[sessionmaker] = None  # type: ignore[type-arg]

    async def initialize(self) -> None:
        """Initialize the database."""
        # Create engine with database-specific configuration
        if self.connection_string.startswith("sqlite"):
            # SQLite doesn't support pool_size and max_overflow
            self.engine = create_engine(self.connection_string, pool_pre_ping=True)
        else:
            # PostgreSQL, MySQL, etc.
            self.engine = create_engine(
                self.connection_string,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20,
            )

        # Create tables
        Base.metadata.create_all(bind=self.engine)

        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )

    def _entry_to_db(self, entry: AuditEntry) -> AuditEntryDB:
        """Convert AuditEntry to database model."""
        # Calculate checksum if not present
        if not entry.checksum:
            entry.checksum = entry.calculate_checksum()

        return AuditEntryDB(
            id=entry.id,
            timestamp=entry.timestamp,
            local_timestamp=entry.local_timestamp,
            user_id=entry.user_id,
            user_name=entry.user_name,
            user_roles=entry.user_roles,
            action=entry.action,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            old_values=entry.old_values,
            new_values=entry.new_values,
            reason=entry.reason,
            reference_id=entry.reference_id,
            application=entry.application,
            module=entry.module,
            function=entry.function,
            ip_address=entry.ip_address,
            user_agent=entry.user_agent,
            session_id=entry.session_id,
            details=entry.details,
            success=entry.success,
            error_message=entry.error_message,
            checksum=entry.checksum,
        )

    def _db_to_entry(self, db_entry: AuditEntryDB) -> AuditEntry:
        """Convert database model to AuditEntry."""
        # SQLAlchemy columns have values at runtime, suppress type checking
        return AuditEntry(
            id=db_entry.id,
            timestamp=db_entry.timestamp,
            local_timestamp=db_entry.local_timestamp,
            user_id=db_entry.user_id,
            user_name=db_entry.user_name,
            user_roles=db_entry.user_roles or [],
            action=db_entry.action,
            entity_type=db_entry.entity_type,
            entity_id=db_entry.entity_id,
            old_values=db_entry.old_values,
            new_values=db_entry.new_values,
            reason=db_entry.reason,
            reference_id=db_entry.reference_id,
            application=db_entry.application,
            module=db_entry.module,
            function=db_entry.function,
            ip_address=db_entry.ip_address,
            user_agent=db_entry.user_agent,
            session_id=db_entry.session_id,
            details=db_entry.details,
            success=db_entry.success,
            error_message=db_entry.error_message,
            checksum=db_entry.checksum,
        )

    async def store(self, entry: AuditEntry) -> None:
        """Store a single audit entry."""
        db_entry = self._entry_to_db(entry)

        if self.SessionLocal is None:  # nosec B101
            raise RuntimeError("Storage not initialized. Call initialize() first.")
        with self.SessionLocal() as session:
            session.add(db_entry)
            session.commit()

    async def store_batch(self, entries: List[AuditEntry]) -> None:
        """Store multiple audit entries efficiently."""
        db_entries = [self._entry_to_db(entry) for entry in entries]

        if self.SessionLocal is None:  # nosec B101
            raise RuntimeError("Storage not initialized. Call initialize() first.")
        with self.SessionLocal() as session:
            session.bulk_save_objects(db_entries)
            session.commit()

    async def query(self, query: AuditQuery) -> List[AuditEntry]:
        """Query audit entries with filters."""
        if self.SessionLocal is None:  # nosec B101
            raise RuntimeError("Storage not initialized. Call initialize() first.")
        with self.SessionLocal() as session:
            q = session.query(AuditEntryDB)

            # Apply time range filter
            if query.start_date:
                q = q.filter(AuditEntryDB.timestamp >= query.start_date)
            if query.end_date:
                q = q.filter(AuditEntryDB.timestamp <= query.end_date)

            # Apply user filters
            if query.user_ids:
                q = q.filter(AuditEntryDB.user_id.in_(query.user_ids))

            # Apply action filters
            if query.actions:
                q = q.filter(AuditEntryDB.action.in_(query.actions))

            # Apply entity filters
            if query.entity_types:
                q = q.filter(AuditEntryDB.entity_type.in_(query.entity_types))
            if query.entity_ids:
                q = q.filter(AuditEntryDB.entity_id.in_(query.entity_ids))

            # Apply success filter
            if query.success_only:
                q = q.filter(AuditEntryDB.success.is_(True))
            elif query.failures_only:
                q = q.filter(AuditEntryDB.success.is_(False))

            # Apply text search
            if query.search_text:
                search_pattern = f"%{query.search_text}%"
                q = q.filter(
                    or_(
                        AuditEntryDB.reason.ilike(search_pattern),
                        AuditEntryDB.error_message.ilike(search_pattern),
                    )
                )

            # Apply sorting
            if query.sort_desc:
                q = q.order_by(desc(getattr(AuditEntryDB, query.sort_by)))
            else:
                q = q.order_by(asc(getattr(AuditEntryDB, query.sort_by)))

            # Apply pagination
            q = q.limit(query.limit).offset(query.offset)

            # Execute and convert results
            results = q.all()
            return [self._db_to_entry(r) for r in results]

    async def get_by_id(self, entry_id: str) -> Optional[AuditEntry]:
        """Get a specific audit entry."""
        if self.SessionLocal is None:  # nosec B101
            raise RuntimeError("Storage not initialized. Call initialize() first.")
        with self.SessionLocal() as session:
            db_entry = (
                session.query(AuditEntryDB).filter(AuditEntryDB.id == entry_id).first()
            )

            if db_entry:
                return self._db_to_entry(db_entry)
            return None

    async def generate_report(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None,
    ) -> AuditReport:
        """Generate comprehensive audit report."""
        import uuid

        report = AuditReport(
            report_id=str(uuid.uuid4()),
            generated_by="system",  # Should be passed in
            start_date=start_date,
            end_date=end_date,
            filters=filters or {},
            total_entries=0,
            total_users=0,
            total_failures=0,
            failure_rate=0.0,
        )

        if self.SessionLocal is None:  # nosec B101
            raise RuntimeError("Storage not initialized. Call initialize() first.")
        with self.SessionLocal() as session:
            # Get all entries in date range
            q = session.query(AuditEntryDB).filter(
                and_(
                    AuditEntryDB.timestamp >= start_date,
                    AuditEntryDB.timestamp <= end_date,
                )
            )

            # Apply additional filters if provided
            if filters:
                if "user_ids" in filters:
                    q = q.filter(AuditEntryDB.user_id.in_(filters["user_ids"]))
                if "actions" in filters:
                    q = q.filter(AuditEntryDB.action.in_(filters["actions"]))

            # Process all entries
            for db_entry in q.all():
                entry = self._db_to_entry(db_entry)
                report.add_entry(entry)

            # Calculate final metrics
            report.calculate_metrics()
            report.detect_anomalies()

        return report

    async def verify_integrity(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Verify integrity of audit entries."""
        results: Dict[str, Any] = {
            "total_checked": 0,
            "valid": 0,
            "invalid": 0,
            "invalid_entries": [],
        }

        if self.SessionLocal is None:  # nosec B101
            raise RuntimeError("Storage not initialized. Call initialize() first.")
        with self.SessionLocal() as session:
            q = session.query(AuditEntryDB)

            if start_date:
                q = q.filter(AuditEntryDB.timestamp >= start_date)
            if end_date:
                q = q.filter(AuditEntryDB.timestamp <= end_date)

            for db_entry in q.all():
                results["total_checked"] += 1

                # Convert to AuditEntry and verify checksum
                entry = self._db_to_entry(db_entry)

                if db_entry.checksum and entry.verify_checksum(db_entry.checksum):
                    results["valid"] += 1
                else:
                    results["invalid"] += 1
                    results["invalid_entries"].append(
                        {
                            "id": entry.id,
                            "timestamp": entry.timestamp.isoformat(),
                            "stored_checksum": db_entry.checksum,
                            "calculated_checksum": entry.calculate_checksum(),
                        }
                    )

        return results

    async def archive_old_entries(
        self, cutoff_date: datetime, archive_location: str
    ) -> int:
        """Archive old audit entries to file."""
        archived_count = 0
        archive_path = Path(archive_location)
        archive_path.mkdir(parents=True, exist_ok=True)

        # Create archive file name with date range
        archive_file = (
            archive_path / f"audit_archive_{cutoff_date.strftime('%Y%m%d')}.jsonl"
        )

        if self.SessionLocal is None:  # nosec B101
            raise RuntimeError("Storage not initialized. Call initialize() first.")
        with self.SessionLocal() as session:
            # Get entries to archive
            entries_to_archive = (
                session.query(AuditEntryDB)
                .filter(AuditEntryDB.timestamp < cutoff_date)
                .all()
            )

            # Write to archive file
            with open(archive_file, "w") as f:
                for db_entry in entries_to_archive:
                    entry = self._db_to_entry(db_entry)
                    f.write(json.dumps(entry.model_dump(), default=str) + "\n")
                    archived_count += 1

            # Note: In production, you might want to delete archived entries
            # But for GxP compliance, it's often better to keep them
            # and just mark them as archived

        return archived_count


class FileAuditStorage(AuditStorage):
    """File-based storage backend for audit trails."""

    def __init__(self, storage_path: str):
        """
        Initialize file-based audit storage.

        Args:
            storage_path: Directory path for storing audit files
        """
        self.storage_path = Path(storage_path)
        self.current_file = None
        self.file_lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize the file storage."""
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Create index file if it doesn't exist
        self.index_file = self.storage_path / "audit_index.db"
        self._init_index()

    def _init_index(self) -> None:
        """Initialize SQLite index for efficient queries."""
        conn = sqlite3.connect(str(self.index_file))
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_index (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT,
                entity_id TEXT,
                success INTEGER NOT NULL DEFAULT 1,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL
            )
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_index(timestamp)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_user_id ON audit_index(user_id)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_action ON audit_index(action)
        """
        )

        conn.commit()
        conn.close()

    def _get_current_file_path(self) -> Path:
        """Get path for current audit file."""
        date_str = datetime.utcnow().strftime("%Y%m%d")
        return self.storage_path / f"audit_{date_str}.jsonl"

    async def store(self, entry: AuditEntry) -> None:
        """Store audit entry to file."""
        # Calculate checksum if not present
        if not entry.checksum:
            entry.checksum = entry.calculate_checksum()

        async with self.file_lock:
            file_path = self._get_current_file_path()

            # Append entry to file
            with open(file_path, "a") as f:
                line_number = (
                    sum(1 for _ in open(file_path)) if file_path.exists() else 0
                )
                f.write(json.dumps(entry.model_dump(), default=str) + "\n")

            # Update index
            conn = sqlite3.connect(str(self.index_file))
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO audit_index
                (id, timestamp, user_id, action, entity_type, entity_id, success,
                 file_path, line_number)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    entry.id,
                    entry.timestamp.isoformat(),
                    entry.user_id,
                    entry.action,
                    entry.entity_type,
                    entry.entity_id,
                    1 if entry.success else 0,
                    str(file_path),
                    line_number,
                ),
            )

            conn.commit()
            conn.close()

    async def store_batch(self, entries: List[AuditEntry]) -> None:
        """Store multiple entries efficiently."""
        for entry in entries:
            await self.store(entry)

    async def query(self, query: AuditQuery) -> List[AuditEntry]:
        """Query audit entries using index."""
        # Build SQL query for index
        conditions = []
        params = []

        if query.start_date:
            conditions.append("timestamp >= ?")
            params.append(query.start_date.isoformat())

        if query.end_date:
            conditions.append("timestamp <= ?")
            params.append(query.end_date.isoformat())

        if query.user_ids:
            placeholders = ",".join("?" * len(query.user_ids))
            conditions.append(f"user_id IN ({placeholders})")
            params.extend(query.user_ids)

        if query.actions:
            placeholders = ",".join("?" * len(query.actions))
            conditions.append(f"action IN ({placeholders})")
            params.extend(query.actions)

        if query.entity_types:
            placeholders = ",".join("?" * len(query.entity_types))
            conditions.append(f"entity_type IN ({placeholders})")
            params.extend(query.entity_types)

        if query.entity_ids:
            placeholders = ",".join("?" * len(query.entity_ids))
            conditions.append(f"entity_id IN ({placeholders})")
            params.extend(query.entity_ids)

        # Apply success filter
        if query.success_only:
            conditions.append("success = 1")
        elif query.failures_only:
            conditions.append("success = 0")

        # Build and execute query
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        order_by = f"timestamp {'DESC' if query.sort_desc else 'ASC'}"

        conn = sqlite3.connect(str(self.index_file))
        cursor = conn.cursor()

        cursor.execute(
            f"""
            SELECT file_path, line_number
            FROM audit_index
            WHERE {where_clause}
            ORDER BY {order_by}
            LIMIT ? OFFSET ?
        """,  # nosec B608
            params + [query.limit, query.offset],
        )

        results = cursor.fetchall()
        conn.close()

        # Load entries from files
        entries = []
        for file_path, line_number in results:
            with open(file_path, "r") as f:
                for i, line in enumerate(f):
                    if i == line_number:
                        data = json.loads(line)
                        entries.append(AuditEntry(**data))
                        break

        return entries

    async def get_by_id(self, entry_id: str) -> Optional[AuditEntry]:
        """Get entry by ID from index."""
        conn = sqlite3.connect(str(self.index_file))
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT file_path, line_number
            FROM audit_index
            WHERE id = ?
        """,
            (entry_id,),
        )

        result = cursor.fetchone()
        conn.close()

        if result:
            file_path, line_number = result
            with open(file_path, "r") as f:
                for i, line in enumerate(f):
                    if i == line_number:
                        data = json.loads(line)
                        return AuditEntry(**data)

        return None

    async def generate_report(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None,
    ) -> AuditReport:
        """Generate report from file storage."""
        # Simple implementation - in production would be more efficient
        query = AuditQuery(
            start_date=start_date,
            end_date=end_date,
            limit=1000,  # Maximum allowed limit for reports
            user_ids=None,
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

        entries = await self.query(query)

        import uuid

        report = AuditReport(
            report_id=str(uuid.uuid4()),
            generated_by="system",
            start_date=start_date,
            end_date=end_date,
            filters=filters or {},
            total_entries=0,
            total_users=0,
            total_failures=0,
            failure_rate=0.0,
        )

        for entry in entries:
            report.add_entry(entry)

        report.calculate_metrics()
        report.detect_anomalies()

        return report

    async def verify_integrity(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Verify integrity of file-based entries."""
        results: Dict[str, Any] = {
            "total_checked": 0,
            "valid": 0,
            "invalid": 0,
            "invalid_entries": [],
        }

        # Get all audit files
        for file_path in sorted(self.storage_path.glob("audit_*.jsonl")):
            with open(file_path, "r") as f:
                for line_num, line in enumerate(f):
                    data = json.loads(line)
                    entry = AuditEntry(**data)

                    # Check date range if specified
                    if start_date and entry.timestamp < start_date:
                        continue
                    if end_date and entry.timestamp > end_date:
                        continue

                    results["total_checked"] += 1

                    # Verify checksum
                    if entry.checksum and entry.verify_checksum(entry.checksum):
                        results["valid"] += 1
                    else:
                        results["invalid"] += 1
                        results["invalid_entries"].append(
                            {
                                "id": entry.id,
                                "file": str(file_path),
                                "line": line_num,
                            }
                        )

        return results

    async def archive_old_entries(
        self, cutoff_date: datetime, archive_location: str
    ) -> int:
        """Archive old audit files."""
        archive_path = Path(archive_location)
        archive_path.mkdir(parents=True, exist_ok=True)

        archived_count = 0
        cutoff_str = cutoff_date.strftime("%Y%m%d")

        for file_path in sorted(self.storage_path.glob("audit_*.jsonl")):
            # Extract date from filename
            file_date_str = file_path.stem.split("_")[1]

            if file_date_str < cutoff_str:
                # Move file to archive
                archive_file = archive_path / file_path.name
                file_path.rename(archive_file)

                # Count entries
                with open(archive_file, "r") as f:
                    archived_count += sum(1 for _ in f)

        return archived_count


# Storage factory
_storage_instances: Dict[str, AuditStorage] = {}


async def get_audit_storage(backend: str = "postgresql", **kwargs: Any) -> AuditStorage:
    """
    Get or create an audit storage instance.

    Args:
        backend: Storage backend type
        **kwargs: Backend-specific parameters

    Returns:
        Audit storage instance
    """
    cache_key = f"{backend}:{json.dumps(kwargs, sort_keys=True)}"

    if cache_key not in _storage_instances:
        if backend == "postgresql":
            connection_string = kwargs.get("connection_string")
            if not connection_string:
                raise ValueError("connection_string is required for postgresql backend")
            storage: AuditStorage = SQLAuditStorage(connection_string)
        elif backend == "file":
            storage_path = kwargs.get("storage_path")
            if not storage_path:
                raise ValueError("storage_path is required for file backend")
            storage = FileAuditStorage(storage_path)
        else:
            raise ValueError(f"Unknown storage backend: {backend}")

        await storage.initialize()
        _storage_instances[cache_key] = storage

    return _storage_instances[cache_key]
