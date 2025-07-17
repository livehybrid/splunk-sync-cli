"""
Unit tests for knowledge objects module.

This module tests the knowledge object management, validation,
and transformation functionality.
"""

import re
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

from splunk_sync.config import KnowledgeObjectConfig
from splunk_sync.exceptions import (FileOperationError, FilterError,
                                    ValidationError)
from splunk_sync.knowledge_objects import (EventTypeHandler, KnowledgeObject,
                                           KnowledgeObjectFilter,
                                           KnowledgeObjectHandler,
                                           KnowledgeObjectManager,
                                           MacroHandler, PropsHandler,
                                           SavedSearchHandler, TagHandler,
                                           TransformHandler,
                                           WorkflowActionHandler)


class TestKnowledgeObject:
    """Test KnowledgeObject dataclass."""

    def test_valid_knowledge_object(self):
        """Test valid knowledge object creation."""
        ko = KnowledgeObject(
            name="test_macro",
            ko_type="macros",
            content={"definition": "index=main"},
            app="search",
        )

        assert ko.name == "test_macro"
        assert ko.ko_type == "macros"
        assert ko.content == {"definition": "index=main"}
        assert ko.app == "search"
        assert ko.owner == "admin"
        assert ko.sharing == "app"

    def test_knowledge_object_with_custom_values(self):
        """Test knowledge object with custom owner and sharing."""
        ko = KnowledgeObject(
            name="test_macro",
            ko_type="macros",
            content={"definition": "index=main"},
            app="search",
            owner="custom_owner",
            sharing="global",
        )

        assert ko.owner == "custom_owner"
        assert ko.sharing == "global"

    def test_knowledge_object_empty_name(self):
        """Test knowledge object with empty name."""
        with pytest.raises(
            ValidationError, match="Knowledge object name cannot be empty"
        ):
            KnowledgeObject(
                name="",
                ko_type="macros",
                content={"definition": "index=main"},
                app="search",
            )

    def test_knowledge_object_empty_content(self):
        """Test knowledge object with empty content."""
        with pytest.raises(
            ValidationError, match="Knowledge object content cannot be empty"
        ):
            KnowledgeObject(
                name="test_macro", ko_type="macros", content={}, app="search"
            )


class TestKnowledgeObjectFilter:
    """Test KnowledgeObjectFilter class."""

    def test_filter_init_valid_regex(self):
        """Test filter initialization with valid regex."""
        config = KnowledgeObjectConfig(savedsearches_allowlist="Alert.*")
        filter_obj = KnowledgeObjectFilter(config)

        assert filter_obj.config == config
        assert filter_obj.savedsearches_pattern.pattern == "Alert.*"

    def test_filter_init_invalid_regex(self):
        """Test filter initialization with invalid regex."""
        config = KnowledgeObjectConfig(savedsearches_allowlist="[invalid")

        with pytest.raises(FilterError, match="Invalid savedsearches allowlist regex"):
            KnowledgeObjectFilter(config)

    def test_should_process_object_enabled_type(self, sample_knowledge_object):
        """Test should_process_object with enabled type."""
        config = KnowledgeObjectConfig(types=["macros"])
        filter_obj = KnowledgeObjectFilter(config)

        assert filter_obj.should_process_object(sample_knowledge_object) is True

    def test_should_process_object_disabled_type(self, sample_knowledge_object):
        """Test should_process_object with disabled type."""
        config = KnowledgeObjectConfig(types=["savedsearches"])
        filter_obj = KnowledgeObjectFilter(config)

        assert filter_obj.should_process_object(sample_knowledge_object) is False

    def test_should_process_object_savedsearches_allowlist_match(
        self, sample_savedsearch
    ):
        """Test should_process_object with savedsearches allowlist match."""
        config = KnowledgeObjectConfig(
            types=["savedsearches"], savedsearches_allowlist="test_.*"
        )
        filter_obj = KnowledgeObjectFilter(config)

        assert filter_obj.should_process_object(sample_savedsearch) is True

    def test_should_process_object_savedsearches_allowlist_no_match(
        self, sample_savedsearch
    ):
        """Test should_process_object with savedsearches allowlist no match."""
        config = KnowledgeObjectConfig(
            types=["savedsearches"], savedsearches_allowlist="Alert.*"
        )
        filter_obj = KnowledgeObjectFilter(config)

        assert filter_obj.should_process_object(sample_savedsearch) is False

    def test_should_process_object_email_actions_not_allowed(self):
        """Test should_process_object with email actions not allowed."""
        ko = KnowledgeObject(
            name="test_alert",
            ko_type="savedsearches",
            content={
                "search": "index=main",
                "action.email": "1",
                "action.email.to": "admin@example.com",
            },
            app="search",
        )

        config = KnowledgeObjectConfig(
            types=["savedsearches"], email_actions_allowed=False
        )
        filter_obj = KnowledgeObjectFilter(config)

        assert filter_obj.should_process_object(ko) is False

    def test_should_process_object_email_actions_allowed(self):
        """Test should_process_object with email actions allowed."""
        ko = KnowledgeObject(
            name="test_alert",
            ko_type="savedsearches",
            content={
                "search": "index=main",
                "action.email": "1",
                "action.email.to": "admin@example.com",
            },
            app="search",
        )

        config = KnowledgeObjectConfig(
            types=["savedsearches"], email_actions_allowed=True
        )
        filter_obj = KnowledgeObjectFilter(config)

        assert filter_obj.should_process_object(ko) is True

    def test_filter_content_ignored_keys(self, sample_knowledge_object):
        """Test filter_content with ignored keys."""
        config = KnowledgeObjectConfig(ignored_keys=["args"])
        filter_obj = KnowledgeObjectFilter(config)

        filtered = filter_obj.filter_content(sample_knowledge_object)

        assert "definition" in filtered
        assert "args" not in filtered

    def test_filter_content_email_actions_not_allowed(self):
        """Test filter_content with email actions not allowed."""
        ko = KnowledgeObject(
            name="test_alert",
            ko_type="savedsearches",
            content={
                "search": "index=main",
                "action.email": "1",
                "action.email.to": "admin@example.com",
                "other_field": "value",
            },
            app="search",
        )

        config = KnowledgeObjectConfig(email_actions_allowed=False)
        filter_obj = KnowledgeObjectFilter(config)

        filtered = filter_obj.filter_content(ko)

        assert "search" in filtered
        assert "other_field" in filtered
        assert "action.email" not in filtered
        assert "action.email.to" not in filtered


class TestSavedSearchHandler:
    """Test SavedSearchHandler class."""

    def test_handler_init(self):
        """Test handler initialization."""
        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        assert handler.ko_type == "savedsearches"
        assert handler.config == config

    def test_validate_valid_savedsearch(self, sample_savedsearch):
        """Test validation of valid savedsearch."""
        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        issues = handler.validate(sample_savedsearch)
        assert issues == []

    def test_validate_missing_search(self):
        """Test validation with missing search field."""
        ko = KnowledgeObject(
            name="test_alert",
            ko_type="savedsearches",
            content={"dispatch.earliest_time": "-1h", "dispatch.latest_time": "now"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        issues = handler.validate(ko)
        assert "search field is required" in issues

    def test_validate_empty_search(self):
        """Test validation with empty search field."""
        ko = KnowledgeObject(
            name="test_alert",
            ko_type="savedsearches",
            content={"search": ""},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        issues = handler.validate(ko)
        assert "search query cannot be empty" in issues

    def test_validate_email_action_missing_to(self):
        """Test validation with email action missing to field."""
        ko = KnowledgeObject(
            name="test_alert",
            ko_type="savedsearches",
            content={"search": "index=main", "action.email": "1"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        issues = handler.validate(ko)
        assert "action.email.to is required when email action is enabled" in issues

    def test_validate_invalid_cron_schedule(self):
        """Test validation with invalid cron schedule."""
        ko = KnowledgeObject(
            name="test_alert",
            ko_type="savedsearches",
            content={"search": "index=main", "cron_schedule": "invalid"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        issues = handler.validate(ko)
        assert any("Invalid cron schedule" in issue for issue in issues)

    def test_validate_cron_schedule_valid(self):
        """Test validation with valid cron schedule."""
        ko = KnowledgeObject(
            name="test_alert",
            ko_type="savedsearches",
            content={"search": "index=main", "cron_schedule": "0 6 * * 1"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        issues = handler.validate(ko)
        assert not any("Invalid cron schedule" in issue for issue in issues)

    def test_transform_for_sync_default_values(self, sample_savedsearch):
        """Test transform_for_sync with default values."""
        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        transformed = handler.transform_for_sync(sample_savedsearch)

        assert transformed["dispatch.earliest_time"] == "-1h"
        assert transformed["dispatch.latest_time"] == "now"
        assert transformed["is_scheduled"] == "1"
        assert transformed["cron_schedule"] == "0 */6 * * *"

    def test_transform_for_sync_unscheduled(self):
        """Test transform_for_sync with unscheduled search."""
        ko = KnowledgeObject(
            name="test_report",
            ko_type="savedsearches",
            content={"search": "index=main | stats count", "is_scheduled": "0"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        transformed = handler.transform_for_sync(ko)

        assert transformed["is_scheduled"] == "0"
        assert (
            "cron_schedule" not in transformed
            or transformed["cron_schedule"] == "0 6 * * 1"
        )

    def test_can_handle_correct_type(self):
        """Test can_handle with correct type."""
        config = KnowledgeObjectConfig()
        handler = SavedSearchHandler(config)

        assert handler.can_handle("savedsearches") is True
        assert handler.can_handle("macros") is False


class TestMacroHandler:
    """Test MacroHandler class."""

    def test_validate_valid_macro(self, sample_knowledge_object):
        """Test validation of valid macro."""
        config = KnowledgeObjectConfig()
        handler = MacroHandler(config)

        issues = handler.validate(sample_knowledge_object)
        assert issues == []

    def test_validate_missing_definition(self):
        """Test validation with missing definition."""
        ko = KnowledgeObject(
            name="test_macro",
            ko_type="macros",
            content={"args": "field1,field2"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = MacroHandler(config)

        issues = handler.validate(ko)
        assert "definition field is required" in issues

    def test_validate_empty_definition(self):
        """Test validation with empty definition."""
        ko = KnowledgeObject(
            name="test_macro",
            ko_type="macros",
            content={"definition": ""},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = MacroHandler(config)

        issues = handler.validate(ko)
        assert "macro definition cannot be empty" in issues

    def test_validate_invalid_args_format(self):
        """Test validation with invalid args format."""
        ko = KnowledgeObject(
            name="test_macro",
            ko_type="macros",
            content={"definition": "index=main", "args": "invalid-arg-format!"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = MacroHandler(config)

        issues = handler.validate(ko)
        assert any("Invalid argument format" in issue for issue in issues)

    def test_transform_for_sync_default_values(self, sample_knowledge_object):
        """Test transform_for_sync with default values."""
        config = KnowledgeObjectConfig()
        handler = MacroHandler(config)

        transformed = handler.transform_for_sync(sample_knowledge_object)

        assert transformed["definition"] == "index=main"
        assert transformed["args"] == "field1,field2"
        assert transformed["validation"] == ""


class TestEventTypeHandler:
    """Test EventTypeHandler class."""

    def test_validate_valid_eventtype(self, sample_eventtype):
        """Test validation of valid eventtype."""
        config = KnowledgeObjectConfig()
        handler = EventTypeHandler(config)

        issues = handler.validate(sample_eventtype)
        assert issues == []

    def test_validate_missing_search(self):
        """Test validation with missing search field."""
        ko = KnowledgeObject(
            name="test_eventtype",
            ko_type="eventtypes",
            content={"priority": "1"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = EventTypeHandler(config)

        issues = handler.validate(ko)
        assert "search field is required" in issues

    def test_validate_invalid_priority(self):
        """Test validation with invalid priority."""
        ko = KnowledgeObject(
            name="test_eventtype",
            ko_type="eventtypes",
            content={"search": "index=main", "priority": "15"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = EventTypeHandler(config)

        issues = handler.validate(ko)
        assert "priority must be between 1 and 10" in issues

    def test_validate_non_numeric_priority(self):
        """Test validation with non-numeric priority."""
        ko = KnowledgeObject(
            name="test_eventtype",
            ko_type="eventtypes",
            content={"search": "index=main", "priority": "invalid"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = EventTypeHandler(config)

        issues = handler.validate(ko)
        assert "priority must be a number" in issues

    def test_transform_for_sync_default_values(self, sample_eventtype):
        """Test transform_for_sync with default values."""
        config = KnowledgeObjectConfig()
        handler = EventTypeHandler(config)

        transformed = handler.transform_for_sync(sample_eventtype)

        assert transformed["search"] == "index=main source=test"
        assert transformed["priority"] == "1"
        assert transformed["disabled"] == "0"


class TestTagHandler:
    """Test TagHandler class."""

    def test_validate_valid_tag(self):
        """Test validation of valid tag."""
        ko = KnowledgeObject(
            name="test_tag",
            ko_type="tags",
            content={"authentication": "enabled", "error": "enabled"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = TagHandler(config)

        issues = handler.validate(ko)
        assert issues == []

    def test_validate_empty_tag_key(self):
        """Test validation with empty tag key."""
        ko = KnowledgeObject(
            name="test_tag",
            ko_type="tags",
            content={"": "enabled", "error": "enabled"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = TagHandler(config)

        issues = handler.validate(ko)
        assert "tag key cannot be empty" in issues

    def test_validate_invalid_tag_value(self):
        """Test validation with invalid tag value."""
        ko = KnowledgeObject(
            name="test_tag",
            ko_type="tags",
            content={"authentication": "invalid", "error": "enabled"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = TagHandler(config)

        issues = handler.validate(ko)
        assert "tag value must be 'enabled' or 'disabled'" in issues

    def test_transform_for_sync_fix_invalid_values(self):
        """Test transform_for_sync fixing invalid values."""
        ko = KnowledgeObject(
            name="test_tag",
            ko_type="tags",
            content={"authentication": "invalid", "error": "enabled"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = TagHandler(config)

        transformed = handler.transform_for_sync(ko)

        assert transformed["authentication"] == "enabled"
        assert transformed["error"] == "enabled"


class TestWorkflowActionHandler:
    """Test WorkflowActionHandler class."""

    def test_validate_valid_workflow_action(self):
        """Test validation of valid workflow action."""
        ko = KnowledgeObject(
            name="test_workflow",
            ko_type="workflow_actions",
            content={"link.method": "get", "link.uri": "http://example.com"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = WorkflowActionHandler(config)

        issues = handler.validate(ko)
        assert issues == []

    def test_validate_missing_method(self):
        """Test validation with missing method."""
        ko = KnowledgeObject(
            name="test_workflow",
            ko_type="workflow_actions",
            content={"link.uri": "http://example.com"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = WorkflowActionHandler(config)

        issues = handler.validate(ko)
        assert "link.method field is required" in issues

    def test_validate_invalid_method(self):
        """Test validation with invalid method."""
        ko = KnowledgeObject(
            name="test_workflow",
            ko_type="workflow_actions",
            content={"link.method": "invalid", "link.uri": "http://example.com"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = WorkflowActionHandler(config)

        issues = handler.validate(ko)
        assert "link.method must be 'get' or 'post'" in issues

    def test_validate_missing_uri(self):
        """Test validation with missing URI."""
        ko = KnowledgeObject(
            name="test_workflow",
            ko_type="workflow_actions",
            content={"link.method": "get"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = WorkflowActionHandler(config)

        issues = handler.validate(ko)
        assert "link.uri field is required" in issues

    def test_transform_for_sync_default_values(self):
        """Test transform_for_sync with default values."""
        ko = KnowledgeObject(
            name="test_workflow",
            ko_type="workflow_actions",
            content={"link.method": "get", "link.uri": "http://example.com"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        handler = WorkflowActionHandler(config)

        transformed = handler.transform_for_sync(ko)

        assert transformed["link.method"] == "get"
        assert transformed["link.uri"] == "http://example.com"
        assert transformed["display_location"] == "field_menu"
        assert transformed["type"] == "link"


class TestKnowledgeObjectManager:
    """Test KnowledgeObjectManager class."""

    def test_manager_init(self):
        """Test manager initialization."""
        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        assert manager.config == config
        assert isinstance(manager.filter, KnowledgeObjectFilter)
        assert "savedsearches" in manager.handlers
        assert "macros" in manager.handlers

    def test_get_handler_existing_type(self):
        """Test getting handler for existing type."""
        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        handler = manager.get_handler("savedsearches")
        assert isinstance(handler, SavedSearchHandler)

    def test_get_handler_nonexistent_type(self):
        """Test getting handler for non-existent type."""
        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        handler = manager.get_handler("nonexistent")
        assert handler is None

    def test_validate_object_success(self, sample_knowledge_object):
        """Test successful object validation."""
        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        issues = manager.validate_object(sample_knowledge_object)
        assert issues == []

    def test_validate_object_no_handler(self):
        """Test object validation with no handler."""
        ko = KnowledgeObject(
            name="test_object",
            ko_type="unknown_type",
            content={"field": "value"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        issues = manager.validate_object(ko)
        assert "No handler available for type: unknown_type" in issues

    def test_transform_object_success(self, sample_knowledge_object):
        """Test successful object transformation."""
        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        transformed = manager.transform_object(sample_knowledge_object)

        assert "definition" in transformed
        assert "args" in transformed
        assert transformed["validation"] == ""

    def test_transform_object_no_handler(self):
        """Test object transformation with no handler."""
        ko = KnowledgeObject(
            name="test_object",
            ko_type="unknown_type",
            content={"field": "value"},
            app="search",
        )

        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        with pytest.raises(
            ValidationError, match="No handler available for type: unknown_type"
        ):
            manager.transform_object(ko)

    def test_should_process_object_true(self, sample_knowledge_object):
        """Test should_process_object returns True."""
        config = KnowledgeObjectConfig(types=["macros"])
        manager = KnowledgeObjectManager(config)

        assert manager.should_process_object(sample_knowledge_object) is True

    def test_should_process_object_false(self, sample_knowledge_object):
        """Test should_process_object returns False."""
        config = KnowledgeObjectConfig(types=["savedsearches"])
        manager = KnowledgeObjectManager(config)

        assert manager.should_process_object(sample_knowledge_object) is False

    @patch("configparser.RawConfigParser")
    def test_load_from_file_success(self, mock_parser, temp_dir):
        """Test successful loading from file."""
        # Create test file
        test_file = temp_dir / "macros.conf"
        test_file.write_text(
            """[test_macro]
definition = index=main
args = field1,field2
"""
        )

        # Mock parser
        mock_config = Mock()
        mock_config.sections.return_value = ["test_macro"]

        mock_config.__getitem__ = lambda self, key: (
            {"definition": "index=main", "args": "field1,field2"}
            if key == "test_macro"
            else (_ for _ in ()).throw(KeyError(key))
        )

        mock_parser.return_value = mock_config

        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        objects = manager.load_from_file(test_file, "macros", "search")

        assert len(objects) == 1
        assert objects[0].name == "test_macro"
        assert objects[0].ko_type == "macros"
        assert objects[0].content["definition"] == "index=main"

    def test_load_from_file_nonexistent(self, temp_dir):
        """Test loading from non-existent file."""
        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        nonexistent_file = temp_dir / "nonexistent.conf"
        objects = manager.load_from_file(nonexistent_file, "macros", "search")

        assert objects == []

    def test_load_from_file_invalid_object(self, temp_dir):
        """Test loading file with invalid object."""
        test_file = temp_dir / "macros.conf"
        test_file.write_text(
            """[invalid_macro]
# Missing definition field
args = field1,field2
"""
        )

        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        with patch("configparser.RawConfigParser") as mock_parser:
            mock_config = Mock()
            mock_config.sections.return_value = ["invalid_macro"]

            mock_config.__getitem__ = lambda self, key: (
                {"args": "field1,field2"}
                if key == "invalid_macro"
                else (_ for _ in ()).throw(KeyError(key))
            )

            mock_parser.return_value = mock_config

            objects = manager.load_from_file(test_file, "macros", "search")

            # Should skip invalid objects
            assert objects == []

    def test_load_from_file_filtered_object(self, temp_dir):
        """Test loading file with filtered object."""
        test_file = temp_dir / "savedsearches.conf"
        test_file.write_text(
            """[filtered_search]
search = index=main
"""
        )

        config = KnowledgeObjectConfig(
            types=["savedsearches"], savedsearches_allowlist="allowed_.*"
        )
        manager = KnowledgeObjectManager(config)

        with patch("configparser.RawConfigParser") as mock_parser:
            mock_config = Mock()
            mock_config.sections.return_value = ["filtered_search"]

            mock_config.__getitem__ = lambda self, key: (
                {"search": "index=main"}
                if key == "filtered_search"
                else (_ for _ in ()).throw(KeyError(key))
            )

            mock_parser.return_value = mock_config

            objects = manager.load_from_file(test_file, "savedsearches", "search")

            # Should skip filtered objects
            assert objects == []

    @patch("configparser.RawConfigParser")
    def test_save_to_file_success(self, mock_parser, temp_dir):
        """Test successful saving to file."""
        objects = [
            KnowledgeObject(
                name="test_macro",
                ko_type="macros",
                content={"definition": "index=main", "args": "field1,field2"},
                app="search",
            )
        ]

        mock_config = Mock()
        mock_parser.return_value = mock_config

        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        test_file = temp_dir / "macros.conf"
        manager.save_to_file(objects, test_file, "macros")

        # Verify file operations
        mock_config.add_section.assert_called_once_with("test_macro")
        mock_config.set.assert_any_call("test_macro", "definition", "index=main")
        mock_config.set.assert_any_call("test_macro", "args", "field1,field2")
        mock_config.set.assert_any_call("test_macro", "validation", "")
        mock_config.write.assert_called_once()

    def test_save_to_file_wrong_type(self, temp_dir):
        """Test saving objects with wrong type."""
        objects = [
            KnowledgeObject(
                name="test_search",
                ko_type="savedsearches",
                content={"search": "index=main"},
                app="search",
            )
        ]

        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        test_file = temp_dir / "macros.conf"

        with patch("configparser.RawConfigParser") as mock_parser:
            mock_config = Mock()
            mock_parser.return_value = mock_config

            manager.save_to_file(objects, test_file, "macros")

            # Should not add section for wrong type
            mock_config.add_section.assert_not_called()

    def test_save_to_file_exception(self, temp_dir):
        """Test saving to file with exception."""
        objects = [
            KnowledgeObject(
                name="test_macro",
                ko_type="macros",
                content={"definition": "index=main"},
                app="search",
            )
        ]

        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        test_file = temp_dir / "macros.conf"

        with patch("configparser.RawConfigParser") as mock_parser:
            mock_config = Mock()
            mock_config.write.side_effect = Exception("Write failed")
            mock_parser.return_value = mock_config

            with pytest.raises(FileOperationError, match="Failed to save macros"):
                manager.save_to_file(objects, test_file, "macros")


class TestKnowledgeObjectsIntegration:
    """Integration tests for knowledge objects module."""

    def test_end_to_end_workflow(self, temp_dir):
        """Test end-to-end workflow with real files."""
        # Create config
        config = KnowledgeObjectConfig(
            types=["macros", "savedsearches"], savedsearches_allowlist="Test.*"
        )
        manager = KnowledgeObjectManager(config)

        # Create test objects
        objects = [
            KnowledgeObject(
                name="test_macro",
                ko_type="macros",
                content={"definition": "index=main", "args": "field1,field2"},
                app="search",
            ),
            KnowledgeObject(
                name="Test_Alert",
                ko_type="savedsearches",
                content={
                    "search": "index=main | stats count",
                    "dispatch.earliest_time": "-1h",
                },
                app="search",
            ),
        ]

        # Save to file
        macros_file = temp_dir / "macros.conf"
        savedsearches_file = temp_dir / "savedsearches.conf"

        manager.save_to_file([objects[0]], macros_file, "macros")
        manager.save_to_file([objects[1]], savedsearches_file, "savedsearches")

        # Load from files
        loaded_macros = manager.load_from_file(macros_file, "macros", "search")
        loaded_savedsearches = manager.load_from_file(
            savedsearches_file, "savedsearches", "search"
        )

        # Verify loaded objects
        assert len(loaded_macros) == 1
        assert len(loaded_savedsearches) == 1

        assert loaded_macros[0].name == "test_macro"
        assert loaded_macros[0].content["definition"] == "index=main"

        assert loaded_savedsearches[0].name == "Test_Alert"
        assert loaded_savedsearches[0].content["search"] == "index=main | stats count"

    def test_validation_and_transformation_workflow(self):
        """Test validation and transformation workflow."""
        config = KnowledgeObjectConfig()
        manager = KnowledgeObjectManager(config)

        # Test valid object
        valid_macro = KnowledgeObject(
            name="valid_macro",
            ko_type="macros",
            content={"definition": "index=main", "args": "field1,field2"},
            app="search",
        )

        issues = manager.validate_object(valid_macro)
        assert issues == []

        transformed = manager.transform_object(valid_macro)
        assert transformed["definition"] == "index=main"
        assert transformed["args"] == "field1,field2"
        assert transformed["validation"] == ""

        # Test invalid object
        invalid_macro = KnowledgeObject(
            name="invalid_macro",
            ko_type="macros",
            content={"args": "field1,field2"},  # Missing definition
            app="search",
        )

        issues = manager.validate_object(invalid_macro)
        assert "definition field is required" in issues

        # Should still transform (handler decides what to do with invalid objects)
        transformed = manager.transform_object(invalid_macro)
        assert "args" in transformed
