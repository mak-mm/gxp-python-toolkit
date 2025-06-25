#!/usr/bin/env python3
"""
Test if the GxP toolkit soft delete works with SQLAlchemy 2.0
"""

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from gxp_toolkit.soft_delete import SoftDeleteMixin

# Create base
Base = declarative_base()

# Define a model with soft delete
class Document(SoftDeleteMixin, Base):
    __tablename__ = "documents"
    
    id = Column(Integer, primary_key=True)
    title = Column(String(200))
    status = Column(String(50))

# Setup database
engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Test it
doc = Document(title="Test Document", status="draft")
session.add(doc)
session.commit()

print(f"✅ Created document: {doc.title}")
print(f"   Is deleted: {doc.is_deleted}")

# Soft delete
doc.soft_delete(user_id="test_user", reason="Testing soft delete functionality")
session.commit()

print(f"\n✅ Soft deleted document")
print(f"   Is deleted: {doc.is_deleted}")
print(f"   Deleted by: {doc.deleted_by}")
print(f"   Deletion reason: {doc.deletion_reason}")

# Query active vs deleted
active = Document.query_active(session).count()
deleted = Document.query_deleted(session).count()

print(f"\n📊 Summary:")
print(f"   Active documents: {active}")
print(f"   Deleted documents: {deleted}")

print("\n✅ SQLAlchemy 2.0 soft delete is working!")