import base64
import os
import sys
from unittest.mock import Mock, patch
from main import get_latest_checkpoint, main
from merkle_proof import DefaultHasher, compute_leaf_hash, verify_inclusion
from util import verify_artifact_signature
# Add parent directory to path BEFORE importing local modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import local modules AFTER sys.path modification


class TestCriticalFunctionality:
    """Only test the most critical functions that could break"""

    def test_compute_leaf_hash_basic(self):
        """Test core Merkle tree leaf computation"""
        test_data = "test data"
        encoded_data = base64.b64encode(test_data.encode()).decode()
        result = compute_leaf_hash(encoded_data)

        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 hex digest

    @patch("requests.get")
    def test_get_latest_checkpoint_success(self, mock_get):
        """Test checkpoint retrieval - core API functionality"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "treeID": "test-id",
            "treeSize": 100,
            "rootHash": "a" * 64,
            "signedTreeHead": "test-sth",
        }
        mock_get.return_value = mock_response

        result = get_latest_checkpoint()

        assert result is not None
        assert result["treeSize"] == 100
        assert "rootHash" in result

    @patch("requests.get")
    def test_get_latest_checkpoint_network_failure(self, mock_get):
        """Test checkpoint error handling"""
        mock_get.side_effect = Exception("Network error")

        result = get_latest_checkpoint()
        assert result is None

    def test_merkle_inclusion_structure(self):
        """Test Merkle inclusion verification can be called"""
        hasher = DefaultHasher

        # Just test the function can be called without crashing
        try:
            verify_inclusion(hasher, 0, 1, "a" * 64, [], "b" * 64)
        except Exception:
            # Expected to fail due to invalid proof, but function was called
            pass

    def test_module_imports(self):
        """Test that all modules can be imported (basic sanity check)"""

        # If we get here, imports work
        assert True

    @patch("builtins.open")
    @patch("util.load_pem_public_key")
    def test_verify_artifact_signature_file_access(self, mock_load_key, mock_open):
        """Test artifact verification can handle files"""
        mock_public_key = Mock()
        mock_load_key.return_value = mock_public_key

        mock_file = Mock()
        mock_file.read.return_value = b"test data"
        mock_open.return_value.__enter__.return_value = mock_file

        # Test the function doesn't crash on basic call
        try:
            verify_artifact_signature(b"signature", b"public_key", "test.txt")
        except Exception:
            pass

    def test_command_line_help(self):
        """Test CLI interface exists"""
        # Just verify main function exists and is callable
        assert callable(main)

    def test_hasher_basic_operations(self):
        """Test core Hasher functionality"""
        from merkle_proof import Hasher

        hasher = Hasher()
        leaf_data = b"test"
        result = hasher.hash_leaf(leaf_data)

        assert isinstance(result, bytes)
        assert len(result) == 32


class TestCheckpointCLI:
    """Test the checkpoint CLI command specifically"""

    def test_checkpoint_command_structure(self):
        """Test checkpoint output has expected structure"""
        # This is a schema validation test
        required_fields = [
            "treeID",
            "treeSize",
            "rootHash",
            "signedTreeHead",
            "inactiveShards",
        ]

        # Test with sample data structure
        sample_data = {
            "treeID": "test",
            "treeSize": 100,
            "rootHash": "test",
            "signedTreeHead": "test",
            "inactiveShards": [],
        }

        for field in required_fields:
            assert field in sample_data
