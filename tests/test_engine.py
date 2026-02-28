import unittest

from src.ngfw_engine import IdentityContext, NGFWEngine, Packet


class TestNGFWEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = NGFWEngine()

    def test_blocks_known_bad_ioc_traffic(self):
        self.engine.intel.update_from_iocs(ja3_hashes={"deadbad"}, ips={"198.51.100.10"})

        packet = Packet(
            src_ip="10.0.0.2",
            dst_ip="198.51.100.10",
            dst_port=4444,
            protocol="TCP",
            bytes_out=2_500_000,
            tls_version="TLS1.0",
            ja3_hash="deadbad",
            user_id="u1",
            device_id="d1",
        )

        identity = IdentityContext(
            user_id="u1",
            device_id="d1",
            user_trust=0.3,
            device_trust=0.3,
            mfa_verified=False,
            geo_velocity_risky=True,
        )

        result = self.engine.evaluate_packet(packet, identity)
        self.assertIn(result.decision, {"block", "quarantine"})

    def test_allows_low_risk_traffic(self):
        packet = Packet(
            src_ip="10.0.0.2",
            dst_ip="10.0.0.8",
            dst_port=443,
            protocol="TCP",
            bytes_out=1400,
            tls_version="TLS1.3",
            ja3_hash="abcdef",
            user_id="u2",
            device_id="d2",
        )

        identity = IdentityContext(
            user_id="u2",
            device_id="d2",
            user_trust=0.95,
            device_trust=0.95,
            mfa_verified=True,
            geo_velocity_risky=False,
        )

        result = self.engine.evaluate_packet(packet, identity)
        self.assertEqual(result.decision, "allow")

    def test_federated_average(self):
        merged = self.engine.federated_average(
            [
                (100, {"w1": 0.2, "w2": 0.4}),
                (300, {"w1": 0.6, "w2": 0.8}),
            ]
        )
        self.assertAlmostEqual(merged["w1"], 0.5)
        self.assertAlmostEqual(merged["w2"], 0.7)


if __name__ == "__main__":
    unittest.main()
