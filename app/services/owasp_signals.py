"""Allowlisted findings from trusted web security telemetry producers."""

COLLECTION = 'web_security_signals'
BATCHES = 'web_service_batches'
SIGNALS = {
    'configuration_policy_failed': ('configuration', 'A02', 'Security configuration policy failed'),
    'supply_chain_policy_failed': ('supply_chain', 'A03', 'Software supply chain policy failed'),
    'crypto_policy_failed': ('cryptography', 'A04', 'Cryptographic policy failed'),
    'injection_blocked': ('injection', 'A05', 'Injection signal blocked by a trusted detector'),
    'business_policy_failed': ('business_design', 'A06', 'Business workflow policy failed'),
    'integrity_check_failed': ('integrity', 'A08', 'Software or data integrity check failed'),
}
