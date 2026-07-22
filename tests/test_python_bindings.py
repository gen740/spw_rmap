import unittest

from pyspw_rmap import _core as spw


class PythonBindingsSmokeTest(unittest.TestCase):
    def test_target_node_fields_round_trip(self) -> None:
        target = spw.TargetNode(0x34, [1, 2, 3], [4, 5, 6, 0])

        self.assertEqual(target.logical_address, 0x34)
        self.assertEqual(target.target_spacewire_address, [1, 2, 3])
        self.assertEqual(target.reply_address, [4, 5, 6, 0])

    def test_debug_toggle_round_trip(self) -> None:
        original = spw.is_debug_enabled()
        try:
            spw.set_debug_enabled(False)
            self.assertFalse(spw.is_debug_enabled())
            spw.enable_debug()
            self.assertTrue(spw.is_debug_enabled())
            spw.disable_debug()
            self.assertFalse(spw.is_debug_enabled())
        finally:
            spw.set_debug_enabled(original)

    def test_client_can_be_constructed_without_connecting(self) -> None:
        client = spw.SpwRmapTCPNode("127.0.0.1", "10030")
        self.assertIsNotNone(client)

    def test_client_context_manager_returns_the_client(self) -> None:
        client = spw.SpwRmapTCPNode("127.0.0.1", "10030")
        with client as managed_client:
            self.assertIs(managed_client, client)


if __name__ == "__main__":
    unittest.main()
