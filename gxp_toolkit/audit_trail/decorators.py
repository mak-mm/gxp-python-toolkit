"""
Decorators for automatic audit trail logging.

These decorators provide easy integration of audit logging into existing code
with minimal changes required.
"""

import asyncio
import functools
import inspect
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar, Union, cast

from .logger import get_audit_logger
from .models import AuditAction

F = TypeVar("F", bound=Callable[..., Any])


def audit_log(
    action: Optional[Union[str, AuditAction]] = None,
    entity_type_param: Optional[str] = None,
    entity_id_param: Optional[str] = None,
    capture_args: bool = True,
    capture_result: bool = True,
    capture_errors: bool = True,
    require_reason: bool = False,
    custom_extractor: Optional[Callable[..., Any]] = None,
) -> Callable[[F], F]:
    """
    Decorator for automatic audit logging of function calls.

    Args:
        action: Audit action (defaults to function name)
        entity_type_param: Parameter name containing entity type
        entity_id_param: Parameter name containing entity ID
        capture_args: Log function arguments
        capture_result: Log function result
        capture_errors: Log errors if function fails
        require_reason: Require 'reason' parameter
        custom_extractor: Custom function to extract audit data

    Returns:
        Decorated function

    Example:
        @audit_log(
            action=AuditAction.UPDATE,
            entity_type_param='model_type',
            entity_id_param='model_id'
        )
        def update_model(model_type: str, model_id: str, data: dict, reason: str):
            # Update logic here
            pass
    """

    def decorator(func: F) -> F:
        # Determine if function is async
        is_async = asyncio.iscoroutinefunction(func)

        if is_async:

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await _execute_with_audit(
                    func,
                    args,
                    kwargs,
                    action,
                    entity_type_param,
                    entity_id_param,
                    capture_args,
                    capture_result,
                    capture_errors,
                    require_reason,
                    custom_extractor,
                )

            return cast(F, async_wrapper)
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Run async audit in sync context
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(
                        _execute_with_audit(
                            func,
                            args,
                            kwargs,
                            action,
                            entity_type_param,
                            entity_id_param,
                            capture_args,
                            capture_result,
                            capture_errors,
                            require_reason,
                            custom_extractor,
                        )
                    )
                finally:
                    loop.close()

            return cast(F, sync_wrapper)

    return decorator


async def _execute_with_audit(
    func: Callable[..., Any],
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
    action: Optional[Union[str, AuditAction]],
    entity_type_param: Optional[str],
    entity_id_param: Optional[str],
    capture_args: bool,
    capture_result: bool,
    capture_errors: bool,
    require_reason: bool,
    custom_extractor: Optional[Callable[..., Any]],
) -> Any:
    """Execute function with audit logging."""
    logger = get_audit_logger()

    # Get function signature
    sig = inspect.signature(func)
    bound_args = sig.bind(*args, **kwargs)
    bound_args.apply_defaults()

    # Determine action
    if action is None:
        # Default to CUSTOM action for unknown function names
        action = AuditAction.CUSTOM

    # Extract entity information
    entity_type = None
    entity_id = None

    if entity_type_param and entity_type_param in bound_args.arguments:
        entity_type = str(bound_args.arguments[entity_type_param])

    if entity_id_param and entity_id_param in bound_args.arguments:
        entity_id = str(bound_args.arguments[entity_id_param])

    # Check for reason if required
    reason = bound_args.arguments.get("reason")
    if require_reason and not reason:
        raise ValueError(
            f"Function {func.__name__} requires a 'reason' parameter for audit logging"
        )

    # Prepare audit details
    details: Dict[str, Any] = {
        "function": func.__name__,
        "module": func.__module__,
    }

    if capture_args:
        # Filter sensitive parameters
        safe_args = {}
        sensitive_params = {"password", "token", "secret", "key", "credential"}

        for param_name, param_value in bound_args.arguments.items():
            if any(sensitive in param_name.lower() for sensitive in sensitive_params):
                safe_args[param_name] = "***REDACTED***"
            else:
                # Truncate large values
                if (
                    isinstance(param_value, (dict, list))
                    and len(str(param_value)) > 1000
                ):
                    safe_args[param_name] = (
                        f"{type(param_value).__name__}(len={len(param_value)})"
                    )
                elif isinstance(param_value, str) and len(param_value) > 500:
                    safe_args[param_name] = param_value[:500] + "...(truncated)"
                else:
                    safe_args[param_name] = param_value

        details["arguments"] = safe_args

    # Custom extraction if provided
    if custom_extractor:
        custom_data = custom_extractor(bound_args.arguments)
        if custom_data:
            details.update(custom_data)

    # Execute function
    success = True
    error_message = None
    result = None
    old_values = None
    new_values = None

    try:
        # For UPDATE actions, try to capture old values
        if action == AuditAction.UPDATE and "old_values" in bound_args.arguments:
            old_values = bound_args.arguments["old_values"]

        # Execute the function
        if asyncio.iscoroutinefunction(func):
            result = await func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)

        # For UPDATE actions, try to capture new values
        if action == AuditAction.UPDATE:
            if "new_values" in bound_args.arguments:
                new_values = bound_args.arguments["new_values"]
            elif capture_result and isinstance(result, dict):
                new_values = result

        # Capture result if requested
        if capture_result and result is not None:
            if isinstance(result, (dict, list)) and len(str(result)) > 1000:
                details["result"] = f"{type(result).__name__}(len={len(result)})"
            elif isinstance(result, str) and len(result) > 500:
                details["result"] = result[:500] + "...(truncated)"
            else:
                details["result"] = result

    except Exception as e:
        success = False
        error_message = str(e)

        if capture_errors:
            details["error_type"] = type(e).__name__
            details["error_message"] = error_message

            # Capture traceback for debugging (truncated)
            import traceback

            tb = traceback.format_exc()
            if len(tb) > 2000:
                tb = tb[:2000] + "...(truncated)"
            details["traceback"] = tb

        # Re-raise the exception
        raise

    finally:
        # Log the audit entry
        try:
            await logger.log_activity(
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                old_values=old_values,
                new_values=new_values,
                reason=reason,
                success=success,
                error_message=error_message,
                details=details,
            )
        except Exception as audit_error:
            # Log audit failure but don't break the application
            import logging

            logging.error(f"Failed to create audit log: {audit_error}")

    return result


def audit_activity(
    action: Union[str, AuditAction],
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    capture_changes: bool = False,
) -> Callable[[F], F]:
    """
    Simplified decorator for common audit scenarios.

    Args:
        action: Action being performed
        entity_type: Type of entity (optional)
        entity_id: Entity identifier (optional)
        capture_changes: Capture before/after values

    Returns:
        Decorated function

    Example:
        @audit_activity(AuditAction.APPROVE, entity_type="Document")
        async def approve_document(doc_id: str, approver: User, reason: str):
            # Approval logic
            pass
    """
    return audit_log(
        action=action,
        entity_type_param="entity_type" if entity_type is None else None,
        entity_id_param="entity_id" if entity_id is None else None,
        capture_args=True,
        capture_result=capture_changes,
        require_reason=action
        in [AuditAction.DELETE, AuditAction.APPROVE, AuditAction.REJECT],
    )


def audit_data_access(
    entity_type: Optional[str] = None,
    log_results: bool = False,
) -> Callable[[F], F]:
    """
    Decorator specifically for data access/read operations.

    Args:
        entity_type: Type of entity being accessed
        log_results: Whether to log the retrieved data

    Returns:
        Decorated function

    Example:
        @audit_data_access(entity_type="PatientRecord")
        def get_patient_record(patient_id: str) -> PatientRecord:
            # Retrieval logic
            pass
    """
    return audit_log(
        action=AuditAction.READ,
        entity_type_param=None if entity_type else "entity_type",
        entity_id_param="entity_id",
        capture_args=True,
        capture_result=log_results,
        capture_errors=True,
        require_reason=False,
    )


def audit_authentication(
    log_failures: bool = True,
    log_password_changes: bool = True,
) -> Callable[[F], F]:
    """
    Decorator for authentication-related functions.

    Args:
        log_failures: Log failed authentication attempts
        log_password_changes: Log password change events

    Returns:
        Decorated function

    Example:
        @audit_authentication()
        async def login(username: str, password: str) -> Optional[User]:
            # Authentication logic
            pass
    """

    def extract_auth_data(args_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Extract authentication-specific data."""
        data = {}

        # Never log passwords, but log username
        if "username" in args_dict:
            data["username"] = args_dict["username"]
        elif "email" in args_dict:
            data["email"] = args_dict["email"]

        # Log IP if available
        if "request" in args_dict and hasattr(args_dict["request"], "client"):
            data["ip_address"] = args_dict["request"].client.host

        return data

    return audit_log(
        action=AuditAction.LOGIN,
        capture_args=False,  # Don't capture raw args (passwords)
        capture_result=True,
        capture_errors=log_failures,
        custom_extractor=extract_auth_data,
    )


def audit_configuration(
    config_type: str,
) -> Callable[[F], F]:
    """
    Decorator for configuration change functions.

    Args:
        config_type: Type of configuration being changed

    Returns:
        Decorated function

    Example:
        @audit_configuration(config_type="SystemSettings")
        def update_system_settings(settings: dict, reason: str) -> dict:
            # Update logic
            pass
    """

    def extract_config_data(args_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configuration change data."""
        data = {"config_type": config_type}

        # Look for before/after values
        if "old_config" in args_dict:
            data["old_config"] = args_dict["old_config"]
        if "new_config" in args_dict:
            data["new_config"] = args_dict["new_config"]
        elif "settings" in args_dict:
            data["new_config"] = args_dict["settings"]

        return data

    return audit_log(
        action=AuditAction.CONFIG_CHANGE,
        capture_args=True,
        capture_result=True,
        require_reason=True,
        custom_extractor=extract_config_data,
    )


# Convenience decorators for common actions
audit_create = functools.partial(audit_activity, action=AuditAction.CREATE)
audit_update = functools.partial(
    audit_activity, action=AuditAction.UPDATE, capture_changes=True
)
audit_delete = functools.partial(audit_activity, action=AuditAction.DELETE)
audit_approve = functools.partial(audit_activity, action=AuditAction.APPROVE)
audit_reject = functools.partial(audit_activity, action=AuditAction.REJECT)
