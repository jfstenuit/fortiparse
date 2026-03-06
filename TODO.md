# TODO – Modular Audit Framework Checks

Each future check MUST be implemented as:
- one module under rules/
- exporting: SECTION, TITLE, run(vdom)

And MUST be placed under the correct section aggregator.

---

## Section 1 – Objects
- [x] Detect duplicate IP addresses  # implemented as `rule_duplicate_ip.py`
- [x] Detect duplicate ranges  # implemented as `rules/rule_duplicate_range.py`
- [x] Detect duplicate FQDN  # implemented as `rules/rule_duplicate_fqdn.py`
- [x] Detect naming inconsistency  # implemented as `rules/rule_naming_inconsistency.py`
- [x] Detect host /32 explosion  # implemented as `rules/rule_host_32_explosion.py`
- [x] Detect tiny ranges  # implemented as `rules/rule_tiny_ranges.py`
- [x] Detect broad services (ALL, ALL_TCP…)  # implemented as `rules/rule_broad_services.py`
- [x] Detect custom services with random ports  # implemented as `rules/rule_custom_services_random_ports.py`
- [x] Detect oversized groups mixing unrelated members  # implemented as `rules/rule_oversized_groups.py`
- [x] Detect unused objects  # implemented as `rules/rule_unused_objects.py`

## Section 2 – Policies
- [x] Detect allow-any rules  # implemented as `rules/rule_allow_any_rules.py`
- [x] Detect redundant / duplicate rules  # implemented as `rules/rule_redundant_rules.py`
- [x] Detect "copy-of" rules  # implemented as `rules/rule_copyof_rules.py`
- [x] Detect disabled rules  # implemented as `rules/rule_disabled_rules.py`
- [x] Detect unjustified NAT  # implemented as `rules/rule_unjustified_nat.py`
- [x] Detect ippool misuse  # implemented as `rules/rule_ippool_misuse.py`

## Section 3 – UTM
- [x] Detect SSL inspection issues  # implemented as `rules/rule_ssl_inspection_issues.py`
- [x] Detect excessive exemptions  # implemented as `rules/rule_excessive_ssl_exemptions.py`
- Webfilter categories fail-open
- [x] DNS filter missing actions  # implemented as `rules/rule_dns_filter_missing_actions.py`
- [x] IPS weak DH groups  # implemented as `rules/rule_ips_weak_dh_groups.py`
- [x] Replay detection disabled  # implemented as `rules/rule_replay_detection_disabled.py`
- [x] Antivirus legacy mode  # implemented as `rules/rule_antivirus_legacy_mode.py`

## Section 4 – VPNs
- [x] Weak crypto (3des, sha1), DH<14, short keylife, PFS disabled  # implemented as `rules/rule_weak_crypto.py`
- PSK reused pattern

## Section 5 – Interfaces / Management
- [x] Exposed management  # implemented as `rules/rule_exposed_management.py`
- [x] Weak certs / factory CA still present  # implemented as `rules/rule_weak_certificates.py`
- [x] SNMP DES / MD5 / v1-v2c / no-ACL  # implemented as `rules/rule_snmp_des.py`

## Section 6 – Dashboards
- Replicated FortiView widgets everywhere