"""
Basic Usage Example - GxP Python Toolkit

IMPORTANT: This is a demonstration file prioritizing readability and educational
value over production readiness. While the GxP Python Toolkit itself is
production-ready, these examples are designed to show minimum viable interactions
and may use simplified patterns, mock objects, or incomplete error handling.

For production use:
- Add comprehensive error handling
- Implement proper authentication/authorization
- Use complete type annotations
- Follow your organization's coding standards
- Add comprehensive logging and monitoring

This example demonstrates how to use the toolkit's core features
for building GxP-compliant applications.
"""

import asyncio
from datetime import datetime

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from gxp_toolkit import (
    AuditLogger,
    GxPConfig,
    SoftDeleteMixin,
    audit_create,
    audit_log,
    audit_update,
)
from gxp_toolkit.audit_trail import AuditAction
from gxp_toolkit.soft_delete import DeletionRequest, SoftDeleteService

# Configure the toolkit
config = GxPConfig(
    application_name="GxP Example App",
    environment="development",
    audit_storage_backend="file",
    audit_retention_days=2555,  # 7 years
    soft_delete_enabled=True,
)

# Set up database
Base = declarative_base()
engine = create_engine("sqlite:///example.db", echo=True)
Session = sessionmaker(bind=engine)


# Define a model with soft delete capability
class Document(Base, SoftDeleteMixin):
    """Example document model with GxP compliance features."""

    __tablename__ = "documents"

    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    content = Column(String(1000))
    status = Column(String(50), default="draft")
    version = Column(Integer, default=1)


# Create tables
Base.metadata.create_all(engine)

# Initialize services
audit_logger = AuditLogger(
    application_name=config.application_name,
    batch_mode=False,  # Immediate writes for demo
)


# Example functions with audit logging
@audit_create(entity_type="Document")
async def create_document(title: str, content: str, user: dict) -> Document:
    """Create a new document with audit trail."""
    # Set audit context
    audit_logger.set_context(user=user)

    # Create document
    session = Session()
    document = Document(
        title=title,
        content=content,
        status="draft",
    )
    session.add(document)
    session.commit()

    print(f"✅ Created document: {document.title} (ID: {document.id})")
    return document


@audit_update(entity_type="Document")
async def update_document(
    doc_id: int, old_values: dict, new_values: dict, user: dict, reason: str
) -> Document:
    """Update a document with change tracking."""
    audit_logger.set_context(user=user)

    session = Session()
    document = session.query(Document).filter(Document.id == doc_id).first()

    if not document:
        raise ValueError(f"Document {doc_id} not found")

    # Update fields
    for key, value in new_values.items():
        if hasattr(document, key):
            setattr(document, key, value)

    # Increment version
    document.version += 1

    session.commit()
    print(f"✅ Updated document: {document.title} " f"(Version: {document.version})")
    return document


@audit_log(action=AuditAction.APPROVE, require_reason=True)
async def approve_document(doc_id: int, user: dict, reason: str) -> Document:
    """Approve a document for release."""
    audit_logger.set_context(user=user)

    session = Session()
    document = session.query(Document).filter(Document.id == doc_id).first()

    if not document:
        raise ValueError(f"Document {doc_id} not found")

    if document.status != "draft":
        raise ValueError("Document must be in draft status to approve")

    document.status = "approved"
    session.commit()

    print(f"✅ Approved document: {document.title}")
    return document


async def soft_delete_document(doc_id: int, user: dict, reason: str) -> dict:
    """Soft delete a document with compliance tracking."""
    session = Session()
    document = session.query(Document).filter(Document.id == doc_id).first()

    if not document:
        raise ValueError(f"Document {doc_id} not found")

    # Create deletion request
    deletion_request = DeletionRequest(
        entity_type="Document",
        entity_id=str(doc_id),
        requester_id=user["id"],
        reason=reason,
    )

    # Use soft delete service
    service = SoftDeleteService(session, audit_logger)
    result = await service.delete_entity(
        entity=document,
        request=deletion_request,
    )

    print(f"🗑️  Soft deleted document: {document.title}")
    return result


async def demonstrate_audit_trail(user: dict):
    """Demonstrate audit trail functionality."""
    print("\n📊 AUDIT TRAIL DEMONSTRATION")
    print("=" * 50)

    # Query recent activities
    from gxp_toolkit.audit_trail import AuditQuery

    query = AuditQuery(
        user_ids=[user["id"]],
        limit=10,
        sort_desc=True,
    )

    entries = await audit_logger.query(query)

    print(f"\nFound {len(entries)} audit entries for user {user['name']}:")
    for entry in entries:
        print(
            f"  - {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | "
            f"{entry.action} | {entry.entity_type or 'N/A'} | "
            f"Success: {entry.success}"
        )

    # Generate compliance report
    report = await audit_logger.generate_report(
        start_date=datetime.utcnow().replace(hour=0, minute=0, second=0),
        end_date=datetime.utcnow(),
        generated_by=user["id"],
    )

    print("\n📈 Audit Report Summary:")
    print(f"  - Total Entries: {report.total_entries}")
    print(f"  - Unique Users: {report.total_users}")
    print("  - Actions by Type:")
    for action, count in report.by_action.items():
        print(f"    • {action}: {count}")

    if report.anomalies:
        print(f"  - ⚠️  Anomalies Detected: {len(report.anomalies)}")


async def main():
    """Run the example demonstration."""
    print("🏥 GxP Python Toolkit - Basic Usage Example")
    print("=" * 50)

    # Define users
    operator_user = {
        "id": "op_001",
        "name": "John Operator",
        "roles": ["operator"],
    }

    qa_user = {
        "id": "qa_001",
        "name": "Jane QA",
        "roles": ["qa", "approver"],
    }

    try:
        # 1. Create a document
        print("\n1️⃣  Creating a new document...")
        doc = await create_document(
            title="SOP-001: Equipment Cleaning Procedure",
            content=(
                "This SOP describes the cleaning procedure for "
                "manufacturing equipment..."
            ),
            user=operator_user,
        )

        # 2. Update the document
        print("\n2️⃣  Updating the document...")
        await update_document(
            doc_id=doc.id,
            old_values={"content": doc.content},
            new_values={
                "content": (doc.content + "\n\nRevision: Added validation steps.")
            },
            user=operator_user,
            reason="Added validation steps per QA feedback QA-2024-001",
        )

        # 3. Approve the document
        print("\n3️⃣  Approving the document...")
        await approve_document(
            doc_id=doc.id,
            user=qa_user,
            reason="Document meets all GMP requirements and has been reviewed",
        )

        # 4. Try to delete (soft delete)
        print("\n4️⃣  Attempting to delete the document...")
        await soft_delete_document(
            doc_id=doc.id,
            user=qa_user,
            reason=("Document superseded by SOP-002 per change control " "CC-2024-005"),
        )

        # 5. Show audit trail
        await demonstrate_audit_trail(qa_user)

        # 6. Verify soft delete
        print("\n5️⃣  Verifying soft delete...")
        session = Session()

        # Active documents (should be empty)
        active_docs = Document.query_active(session).all()
        print(f"  - Active documents: {len(active_docs)}")

        # All documents including deleted
        all_docs = Document.query_all(session).all()
        print(f"  - Total documents (including deleted): {len(all_docs)}")

        # Deleted documents
        deleted_docs = Document.query_deleted(session).all()
        print(f"  - Deleted documents: {len(deleted_docs)}")

        if deleted_docs:
            deleted_doc = deleted_docs[0]
            print(f"    • Deleted by: {deleted_doc.deleted_by}")
            print(f"    • Deletion reason: {deleted_doc.deletion_reason}")

        session.close()

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()

    print("\n✅ Example completed successfully!")
    print("Check 'audit_logs/' directory for audit trail files.")


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
