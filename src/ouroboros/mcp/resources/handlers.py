"""Ouroboros resource handlers for MCP server.

This module defines resource handlers for exposing Ouroboros data:
- seeds: Access to seed definitions
- sessions: Access to session data
- events: Access to event history
"""

from collections.abc import Sequence
from dataclasses import dataclass
import re
from urllib.parse import urlparse

import structlog

from ouroboros.core.types import Result
from ouroboros.mcp.errors import MCPResourceNotFoundError, MCPServerError
from ouroboros.mcp.types import MCPResourceContent, MCPResourceDefinition

log = structlog.get_logger(__name__)


def _validate_uri_format(uri: str, expected_scheme: str = "ouroboros") -> tuple[bool, str | None]:
    """Validate URI format for security and correctness.

    Args:
        uri: The URI to validate.
        expected_scheme: Expected URI scheme (default: "ouroboros").

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not uri:
        return False, "URI cannot be empty"

    # Check for dangerous characters
    dangerous_chars = ["<", ">", "\"", "'", "`", "\0", "\n", "\r"]
    for char in dangerous_chars:
        if char in uri:
            return False, f"URI contains dangerous character: {repr(char)}"

    # Parse URI
    try:
        parsed = urlparse(uri)
    except Exception as e:
        return False, f"Invalid URI format: {e}"

    # Check scheme
    if not parsed.scheme:
        return False, "URI must include a scheme (e.g., ouroboros://)"

    if parsed.scheme != expected_scheme:
        return False, f"Invalid URI scheme: expected '{expected_scheme}', got '{parsed.scheme}'"

    # Check for valid path structure (no path traversal, proper format)
    path = parsed.path
    if not path or path == "/":
        # Root path is allowed for listing resources
        return True, None

    # Check for path traversal attempts
    if ".." in path or path.startswith("//"):
        return False, "URI contains path traversal pattern"

    # Validate path contains only safe characters
    # Allow: alphanumeric, hyphen, underscore, forward slash
    if not re.match(r'^[a-zA-Z0-9/_-]+$', path):
        return False, "URI path contains invalid characters"

    return True, None


@dataclass
class SeedsResourceHandler:
    """Handler for seed resources.

    Provides access to seed definitions and content.
    URI patterns:
    - ouroboros://seeds - List all seeds
    - ouroboros://seeds/{seed_id} - Get specific seed
    """

    @property
    def definitions(self) -> Sequence[MCPResourceDefinition]:
        """Return the resource definitions."""
        return (
            MCPResourceDefinition(
                uri="ouroboros://seeds",
                name="Seeds List",
                description="List of all available seeds in the system",
                mime_type="application/json",
            ),
        )

    async def handle(
        self,
        uri: str,
    ) -> Result[MCPResourceContent, MCPServerError]:
        """Handle a seed resource request.

        Args:
            uri: The resource URI.

        Returns:
            Result containing resource content or error.
        """
        log.info("mcp.resource.seeds", uri=uri)

        # Validate URI format
        is_valid, error_msg = _validate_uri_format(uri)
        if not is_valid:
            log.warning("mcp.resource.invalid_uri", uri=uri, error=error_msg)
            return Result.err(
                MCPServerError(
                    f"Invalid URI format: {error_msg}",
                    details={"uri": uri},
                )
            )

        try:
            if uri == "ouroboros://seeds":
                # TODO: Integrate with actual seed storage
                content = (
                    '{"seeds": [\n'
                    '  {"id": "seed-001", "name": "Example Seed", "status": "active"},\n'
                    '  {"id": "seed-002", "name": "Another Seed", "status": "completed"}\n'
                    "]}"
                )
                return Result.ok(
                    MCPResourceContent(
                        uri=uri,
                        text=content,
                        mime_type="application/json",
                    )
                )

            # Handle specific seed ID
            if uri.startswith("ouroboros://seeds/"):
                seed_id = uri.replace("ouroboros://seeds/", "")
                # TODO: Fetch actual seed
                content = (
                    f'{{"id": "{seed_id}", '
                    f'"name": "Seed {seed_id}", '
                    f'"content": "Example seed content...", '
                    f'"status": "active"}}'
                )
                return Result.ok(
                    MCPResourceContent(
                        uri=uri,
                        text=content,
                        mime_type="application/json",
                    )
                )

            return Result.err(
                MCPResourceNotFoundError(
                    f"Unknown seed resource: {uri}",
                    resource_type="seed",
                    resource_id=uri,
                )
            )
        except Exception as e:
            log.error("mcp.resource.seeds.error", uri=uri, error=str(e))
            return Result.err(
                MCPServerError(f"Failed to read seed resource: {e}")
            )


@dataclass
class SessionsResourceHandler:
    """Handler for session resources.

    Provides access to session data and status.
    URI patterns:
    - ouroboros://sessions - List all sessions
    - ouroboros://sessions/current - Get current active session
    - ouroboros://sessions/{session_id} - Get specific session
    """

    @property
    def definitions(self) -> Sequence[MCPResourceDefinition]:
        """Return the resource definitions."""
        return (
            MCPResourceDefinition(
                uri="ouroboros://sessions",
                name="Sessions List",
                description="List of all sessions",
                mime_type="application/json",
            ),
            MCPResourceDefinition(
                uri="ouroboros://sessions/current",
                name="Current Session",
                description="The currently active session",
                mime_type="application/json",
            ),
        )

    async def handle(
        self,
        uri: str,
    ) -> Result[MCPResourceContent, MCPServerError]:
        """Handle a session resource request.

        Args:
            uri: The resource URI.

        Returns:
            Result containing resource content or error.
        """
        log.info("mcp.resource.sessions", uri=uri)

        # Validate URI format
        is_valid, error_msg = _validate_uri_format(uri)
        if not is_valid:
            log.warning("mcp.resource.invalid_uri", uri=uri, error=error_msg)
            return Result.err(
                MCPServerError(
                    f"Invalid URI format: {error_msg}",
                    details={"uri": uri},
                )
            )

        try:
            if uri == "ouroboros://sessions":
                # TODO: Integrate with actual session management
                content = (
                    '{"sessions": [\n'
                    '  {"id": "session-001", "status": "active", "phase": "execution"},\n'
                    '  {"id": "session-002", "status": "completed", "phase": "done"}\n'
                    "]}"
                )
                return Result.ok(
                    MCPResourceContent(
                        uri=uri,
                        text=content,
                        mime_type="application/json",
                    )
                )

            if uri == "ouroboros://sessions/current":
                # TODO: Get actual current session
                content = (
                    '{"id": "session-001", '
                    '"status": "active", '
                    '"phase": "execution", '
                    '"progress": 0.6, '
                    '"current_iteration": 3, '
                    '"max_iterations": 10}'
                )
                return Result.ok(
                    MCPResourceContent(
                        uri=uri,
                        text=content,
                        mime_type="application/json",
                    )
                )

            # Handle specific session ID
            if uri.startswith("ouroboros://sessions/"):
                session_id = uri.replace("ouroboros://sessions/", "")
                # TODO: Fetch actual session
                content = (
                    f'{{"id": "{session_id}", '
                    f'"status": "active", '
                    f'"phase": "execution", '
                    f'"seed_id": "seed-001"}}'
                )
                return Result.ok(
                    MCPResourceContent(
                        uri=uri,
                        text=content,
                        mime_type="application/json",
                    )
                )

            return Result.err(
                MCPResourceNotFoundError(
                    f"Unknown session resource: {uri}",
                    resource_type="session",
                    resource_id=uri,
                )
            )
        except Exception as e:
            log.error("mcp.resource.sessions.error", uri=uri, error=str(e))
            return Result.err(
                MCPServerError(f"Failed to read session resource: {e}")
            )


@dataclass
class EventsResourceHandler:
    """Handler for event resources.

    Provides access to event history.
    URI patterns:
    - ouroboros://events - List recent events
    - ouroboros://events/{session_id} - Events for a specific session
    """

    @property
    def definitions(self) -> Sequence[MCPResourceDefinition]:
        """Return the resource definitions."""
        return (
            MCPResourceDefinition(
                uri="ouroboros://events",
                name="Events",
                description="Recent event history",
                mime_type="application/json",
            ),
        )

    async def handle(
        self,
        uri: str,
    ) -> Result[MCPResourceContent, MCPServerError]:
        """Handle an events resource request.

        Args:
            uri: The resource URI.

        Returns:
            Result containing resource content or error.
        """
        log.info("mcp.resource.events", uri=uri)

        # Validate URI format
        is_valid, error_msg = _validate_uri_format(uri)
        if not is_valid:
            log.warning("mcp.resource.invalid_uri", uri=uri, error=error_msg)
            return Result.err(
                MCPServerError(
                    f"Invalid URI format: {error_msg}",
                    details={"uri": uri},
                )
            )

        try:
            if uri == "ouroboros://events":
                # TODO: Integrate with actual event store
                content = (
                    '{"events": [\n'
                    '  {"id": "evt-001", "type": "execution", "session_id": "session-001", '
                    '"timestamp": "2025-01-25T10:00:00Z"},\n'
                    '  {"id": "evt-002", "type": "evaluation", "session_id": "session-001", '
                    '"timestamp": "2025-01-25T10:01:00Z"}\n'
                    "]}"
                )
                return Result.ok(
                    MCPResourceContent(
                        uri=uri,
                        text=content,
                        mime_type="application/json",
                    )
                )

            # Handle session-specific events
            if uri.startswith("ouroboros://events/"):
                session_id = uri.replace("ouroboros://events/", "")
                # TODO: Fetch actual events for session
                content = (
                    f'{{"session_id": "{session_id}", "events": [\n'
                    f'  {{"id": "evt-001", "type": "execution", '
                    f'"timestamp": "2025-01-25T10:00:00Z"}},\n'
                    f'  {{"id": "evt-002", "type": "evaluation", '
                    f'"timestamp": "2025-01-25T10:01:00Z"}}\n'
                    f"]}}"
                )
                return Result.ok(
                    MCPResourceContent(
                        uri=uri,
                        text=content,
                        mime_type="application/json",
                    )
                )

            return Result.err(
                MCPResourceNotFoundError(
                    f"Unknown events resource: {uri}",
                    resource_type="events",
                    resource_id=uri,
                )
            )
        except Exception as e:
            log.error("mcp.resource.events.error", uri=uri, error=str(e))
            return Result.err(
                MCPServerError(f"Failed to read events resource: {e}")
            )


# Convenience functions for handler access
def seeds_handler() -> SeedsResourceHandler:
    """Create a SeedsResourceHandler instance."""
    return SeedsResourceHandler()


def sessions_handler() -> SessionsResourceHandler:
    """Create a SessionsResourceHandler instance."""
    return SessionsResourceHandler()


def events_handler() -> EventsResourceHandler:
    """Create an EventsResourceHandler instance."""
    return EventsResourceHandler()


# List of all Ouroboros resources for registration
OUROBOROS_RESOURCES: tuple[
    SeedsResourceHandler | SessionsResourceHandler | EventsResourceHandler, ...
] = (
    SeedsResourceHandler(),
    SessionsResourceHandler(),
    EventsResourceHandler(),
)
