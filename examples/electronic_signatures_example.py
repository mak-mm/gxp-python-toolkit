#!/usr/bin/env python3
"""
Electronic Signatures Example - GxP Python Toolkit

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

Demonstrates 21 CFR Part 11 compliant electronic signatures:
- Multi-level approval workflows
- Signature verification
- Signature manifests for batch operations
- Integration with audit trail
"""

from datetime import datetime

from gxp_toolkit.access_control import User
from gxp_toolkit.audit_trail import audit_event
from gxp_toolkit.electronic_signatures import (
    ElectronicSignature,
    SignatureManifest,
    SignaturePurpose,
    require_signature,
    verify_signature_manifest,
)


# Example: Document requiring multiple signatures
class ClinicalProtocol:
    """Example document requiring electronic signatures."""

    def __init__(self, protocol_id: str, title: str):
        self.protocol_id = protocol_id
        self.title = title
        self.version = "1.0"
        self.status = "draft"
        self.content = ""
        self.signatures = []

    def add_signature(self, signature: ElectronicSignature):
        """Add a signature to the protocol."""
        self.signatures.append(signature)
        audit_event(
            action="protocol.signed",
            resource_type="clinical_protocol",
            resource_id=self.protocol_id,
            details={
                "signer": signature.user_name,
                "purpose": signature.purpose,
                "version": self.version,
            },
        )


# Decorated function requiring signature
@require_signature(purpose=SignaturePurpose.APPROVAL)
def approve_protocol(protocol: ClinicalProtocol, user: User) -> bool:
    """Approve a clinical protocol (requires electronic signature)."""
    protocol.status = "approved"
    print(f"✓ Protocol {protocol.protocol_id} approved by {user.name}")
    return True


def main():
    """Demonstrate electronic signature workflows."""
    print("✍️  Electronic Signatures Example (21 CFR Part 11)\n")

    # Create a sample protocol
    protocol = ClinicalProtocol(
        protocol_id="PROT-2024-001", title="Phase 3 Clinical Trial Protocol"
    )

    # 1. Single Signature Example
    print("1️⃣ Single Electronic Signature:")

    # Create author signature
    author_sig = ElectronicSignature.create_signature(
        user_id="researcher@pharma.com",
        user_name="Dr. Jane Smith",
        purpose=SignaturePurpose.AUTHORSHIP,
        password="secure-password-123",  # In production, use secure input
    )

    print(f"  Author: {author_sig.user_name}")
    print(f"  Purpose: {author_sig.purpose}")
    print(f"  Timestamp: {author_sig.timestamp}")
    print(f"  Valid: {author_sig.is_valid()}")

    protocol.add_signature(author_sig)
    print("  ✓ Author signature added\n")

    # 2. Multi-Level Approval Workflow
    print("2️⃣ Multi-Level Approval Workflow:")

    # Create signature manifest for approval process
    manifest = SignatureManifest(
        manifest_id=f"MANIFEST-{protocol.protocol_id}",
        document_type="clinical_protocol",
        document_id=protocol.protocol_id,
        required_signatures=[
            {
                "role": "author",
                "purpose": SignaturePurpose.AUTHORSHIP,
                "required": True,
            },
            {"role": "reviewer", "purpose": SignaturePurpose.REVIEW, "required": True},
            {
                "role": "approver",
                "purpose": SignaturePurpose.APPROVAL,
                "required": True,
            },
        ],
    )

    # Add signatures in sequence
    signatures = []

    # Author already signed
    manifest.add_signature(author_sig)
    signatures.append(author_sig)
    print("  ✓ Author signature recorded in manifest")

    # Reviewer signature
    reviewer_sig = ElectronicSignature.create_signature(
        user_id="reviewer@pharma.com",
        user_name="Dr. John Davis",
        purpose=SignaturePurpose.REVIEW,
        password="review-password-456",
        metadata={
            "review_comments": "Protocol meets all regulatory requirements",
            "review_date": datetime.utcnow().isoformat(),
        },
    )
    manifest.add_signature(reviewer_sig)
    signatures.append(reviewer_sig)
    protocol.add_signature(reviewer_sig)
    print("  ✓ Reviewer signature added")

    # Final approval signature
    approval_sig = ElectronicSignature.create_signature(
        user_id="director@pharma.com",
        user_name="Dr. Sarah Johnson",
        purpose=SignaturePurpose.APPROVAL,
        password="approval-password-789",
        metadata={
            "approval_condition": "Pending ethics committee review",
            "effective_date": "2024-02-01",
        },
    )
    manifest.add_signature(approval_sig)
    signatures.append(approval_sig)
    protocol.add_signature(approval_sig)
    print("  ✓ Approval signature added")

    # Verify manifest completion
    is_complete = manifest.is_complete()
    print(f"\n  Manifest complete: {is_complete}")
    print(f"  Total signatures: {len(manifest.signatures)}")

    # 3. Signature Verification
    print("\n3️⃣ Signature Verification:")

    # Verify individual signatures
    for sig in signatures:
        is_valid = sig.is_valid()
        print(
            f"  {sig.user_name} ({sig.purpose}): "
            f"{'✓ Valid' if is_valid else '✗ Invalid'}"
        )

    # Verify manifest integrity
    manifest_valid = verify_signature_manifest(manifest)
    print(f"\n  Manifest integrity: " f"{'✓ Valid' if manifest_valid else '✗ Invalid'}")

    # 4. Signature Report
    print("\n4️⃣ Signature Report:")
    print(f"\n  Document: {protocol.title}")
    print(f"  ID: {protocol.protocol_id}")
    print(f"  Status: {protocol.status}")
    print("\n  Signatures:")
    print("  " + "-" * 70)
    print(f"  {'Signer':<25} {'Purpose':<15} {'Timestamp':<20} {'Valid':<10}")
    print("  " + "-" * 70)

    for sig in protocol.signatures:
        timestamp = sig.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        valid = "✓" if sig.is_valid() else "✗"
        print(
            f"  {sig.user_name:<25} {sig.purpose:<15} " f"{timestamp:<20} {valid:<10}"
        )

    # 5. Compliance Features
    print("\n5️⃣ 21 CFR Part 11 Compliance Features:")
    print("  ✓ Signatures are attributable to individuals")
    print("  ✓ Signatures include timestamp and purpose")
    print("  ✓ Signatures cannot be modified after creation")
    print("  ✓ All signature events are logged to audit trail")
    print("  ✓ Multi-factor authentication supported")
    print("  ✓ Password verification required")
    print("  ✓ Signature manifests ensure complete approval chains")

    # 6. Advanced Usage - Decorated Functions
    print("\n6️⃣ Using Signature Decorators:")

    # Create a mock user (not used in this example)
    # approver = User(
    #     id="director@pharma.com",
    #     email="director@pharma.com",
    #     name="Dr. Sarah Johnson",
    #     roles=["Clinical Director"],
    #     permissions={Permission.APPROVE},
    # )

    # This would normally prompt for signature
    print("  Calling function that requires signature...")
    print("  (In production, this would show signature dialog)")

    # The decorator would handle signature collection
    # approve_protocol(protocol, approver)

    print("\n✅ Electronic signature example completed!")
    print("   Remember: Electronic signatures in GxP must be:")
    print("   • Unique to one individual")
    print("   • Not reused or reassigned")
    print("   • Protected against modification")
    print("   • Linked to their respective records")


if __name__ == "__main__":
    main()
