"""Tests for tool registry."""

import threading
from typing import Any

import pytest

from ouroboros.core.types import Result
from ouroboros.mcp.errors import MCPResourceNotFoundError, MCPServerError
from ouroboros.mcp.tools.registry import ToolRegistry, get_global_registry
from ouroboros.mcp.types import (
    ContentType,
    MCPContentItem,
    MCPToolDefinition,
    MCPToolParameter,
    MCPToolResult,
    ToolInputType,
)


class MockToolHandler:
    """Mock tool handler for testing."""

    def __init__(self, name: str = "mock_tool") -> None:
        self._name = name
        self._call_count = 0

    @property
    def definition(self) -> MCPToolDefinition:
        return MCPToolDefinition(
            name=self._name,
            description=f"Mock tool: {self._name}",
            parameters=(
                MCPToolParameter(
                    name="input",
                    type=ToolInputType.STRING,
                ),
            ),
        )

    async def handle(
        self, arguments: dict[str, Any]
    ) -> Result[MCPToolResult, MCPServerError]:
        self._call_count += 1
        return Result.ok(
            MCPToolResult(
                content=(
                    MCPContentItem(
                        type=ContentType.TEXT,
                        text=f"Called with: {arguments}",
                    ),
                ),
            )
        )


class TestToolRegistry:
    """Test ToolRegistry class."""

    def test_registry_starts_empty(self) -> None:
        """New registry has no tools."""
        registry = ToolRegistry()
        assert registry.tool_count == 0

    def test_register_tool(self) -> None:
        """register adds a tool handler."""
        registry = ToolRegistry()
        handler = MockToolHandler("test_tool")

        registry.register(handler)

        assert registry.tool_count == 1
        assert registry.has_tool("test_tool")

    def test_register_duplicate_fails(self) -> None:
        """Registering duplicate tool name fails."""
        registry = ToolRegistry()
        handler = MockToolHandler("test_tool")

        registry.register(handler)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(handler)

    def test_register_all(self) -> None:
        """register_all adds multiple handlers."""
        registry = ToolRegistry()
        handlers = [
            MockToolHandler("tool1"),
            MockToolHandler("tool2"),
            MockToolHandler("tool3"),
        ]

        registry.register_all(handlers)

        assert registry.tool_count == 3

    def test_unregister_tool(self) -> None:
        """unregister removes a tool handler."""
        registry = ToolRegistry()
        handler = MockToolHandler("test_tool")

        registry.register(handler)
        result = registry.unregister("test_tool")

        assert result is True
        assert not registry.has_tool("test_tool")

    def test_unregister_nonexistent(self) -> None:
        """unregister returns False for unknown tool."""
        registry = ToolRegistry()
        result = registry.unregister("nonexistent")
        assert result is False

    def test_get_handler(self) -> None:
        """get returns the handler for a tool."""
        registry = ToolRegistry()
        handler = MockToolHandler("test_tool")

        registry.register(handler)
        retrieved = registry.get("test_tool")

        assert retrieved is handler

    def test_get_nonexistent(self) -> None:
        """get returns None for unknown tool."""
        registry = ToolRegistry()
        assert registry.get("nonexistent") is None

    def test_list_tools(self) -> None:
        """list_tools returns all tool definitions."""
        registry = ToolRegistry()
        registry.register(MockToolHandler("tool1"))
        registry.register(MockToolHandler("tool2"))

        tools = registry.list_tools()

        assert len(tools) == 2
        names = {t.name for t in tools}
        assert names == {"tool1", "tool2"}


class TestToolRegistryCategories:
    """Test ToolRegistry category functionality."""

    def test_register_with_category(self) -> None:
        """Tools can be registered in categories."""
        registry = ToolRegistry()

        registry.register(MockToolHandler("tool1"), category="cat1")
        registry.register(MockToolHandler("tool2"), category="cat1")
        registry.register(MockToolHandler("tool3"), category="cat2")

        assert len(registry.list_categories()) == 2

    def test_list_tools_by_category(self) -> None:
        """list_tools can filter by category."""
        registry = ToolRegistry()

        registry.register(MockToolHandler("tool1"), category="cat1")
        registry.register(MockToolHandler("tool2"), category="cat1")
        registry.register(MockToolHandler("tool3"), category="cat2")

        cat1_tools = registry.list_tools(category="cat1")
        assert len(cat1_tools) == 2

        cat2_tools = registry.list_tools(category="cat2")
        assert len(cat2_tools) == 1

    def test_tools_in_category(self) -> None:
        """tools_in_category returns tool names."""
        registry = ToolRegistry()

        registry.register(MockToolHandler("tool1"), category="my_cat")
        registry.register(MockToolHandler("tool2"), category="my_cat")

        tools = registry.tools_in_category("my_cat")
        assert set(tools) == {"tool1", "tool2"}


class TestToolRegistryCall:
    """Test ToolRegistry call functionality."""

    async def test_call_tool(self) -> None:
        """call invokes the tool handler."""
        registry = ToolRegistry()
        handler = MockToolHandler("test_tool")
        registry.register(handler)

        result = await registry.call("test_tool", {"input": "hello"})

        assert result.is_ok
        assert "hello" in result.value.text_content
        assert handler._call_count == 1

    async def test_call_nonexistent_tool(self) -> None:
        """call returns error for unknown tool."""
        registry = ToolRegistry()

        result = await registry.call("nonexistent", {})

        assert result.is_err
        assert isinstance(result.error, MCPResourceNotFoundError)

    def test_get_definition(self) -> None:
        """get_definition returns tool definition."""
        registry = ToolRegistry()
        handler = MockToolHandler("test_tool")
        registry.register(handler)

        defn = registry.get_definition("test_tool")

        assert defn is not None
        assert defn.name == "test_tool"

    def test_get_definition_nonexistent(self) -> None:
        """get_definition returns None for unknown tool."""
        registry = ToolRegistry()
        assert registry.get_definition("nonexistent") is None

    def test_clear(self) -> None:
        """clear removes all tools."""
        registry = ToolRegistry()
        registry.register(MockToolHandler("tool1"))
        registry.register(MockToolHandler("tool2"))

        registry.clear()

        assert registry.tool_count == 0


class TestGlobalRegistry:
    """Test global registry functionality."""

    def test_get_global_registry(self) -> None:
        """get_global_registry returns the same instance."""
        registry1 = get_global_registry()
        registry2 = get_global_registry()

        assert registry1 is registry2

    def test_global_registry_thread_safety(self) -> None:
        """Global registry initialization is thread-safe (TOCTOU protection)."""
        # Reset global registry to test initialization
        import ouroboros.mcp.tools.registry as registry_module

        original = registry_module._global_registry
        registry_module._global_registry = None

        try:
            registries: list[ToolRegistry] = []
            errors: list[Exception] = []

            def get_registry() -> None:
                try:
                    registry = get_global_registry()
                    registries.append(registry)
                except Exception as e:
                    errors.append(e)

            # Create multiple threads that try to get the global registry
            threads = [threading.Thread(target=get_registry) for _ in range(10)]

            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Should have no errors
            assert len(errors) == 0, f"Thread safety violations: {errors}"

            # All threads should get the same instance
            assert len(registries) == 10
            assert all(r is registries[0] for r in registries), (
                "All threads should get the same registry instance"
            )
        finally:
            # Restore original registry
            registry_module._global_registry = original


class TestRegistryConcurrency:
    """Test concurrent access to tool registry."""

    async def test_concurrent_tool_calls(self) -> None:
        """Registry handles concurrent tool calls safely."""
        import asyncio

        registry = ToolRegistry()
        handler = MockToolHandler("concurrent_tool")
        registry.register(handler)

        # Make multiple concurrent calls
        results = await asyncio.gather(
            *[
                registry.call("concurrent_tool", {"input": f"call-{i}"})
                for i in range(20)
            ]
        )

        # All calls should succeed
        assert all(r.is_ok for r in results)
        assert handler._call_count == 20

    def test_concurrent_registration(self) -> None:
        """Registry handles concurrent registration safely."""
        registry = ToolRegistry()
        errors: list[Exception] = []
        success_count = [0]

        def register_tool(tool_id: int) -> None:
            try:
                handler = MockToolHandler(f"tool-{tool_id}")
                registry.register(handler)
                success_count[0] += 1
            except ValueError:
                # Expected for duplicate names
                pass
            except Exception as e:
                errors.append(e)

        # Register tools from multiple threads
        threads = [threading.Thread(target=register_tool, args=(i,)) for i in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have no unexpected errors
        assert len(errors) == 0, f"Unexpected errors: {errors}"
        assert success_count[0] == 10, "All unique registrations should succeed"
        assert registry.tool_count == 10
