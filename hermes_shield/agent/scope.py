"""HermesShield Scope Enforcement.

Enforces security scope boundaries - agent refuses to operate outside declared target scope.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Set
from enum import Enum
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ScopeType(Enum):
    """Types of scope declarations."""
    IP_RANGE = "ip_range"
    DOMAIN = "domain"
    URL = "url"
    NETWORK = "network"
    CIDR = "cidr"
    ASN = "asn"


class ScopeViolation(Exception):
    """Raised when an action violates scope boundaries."""
    pass


@dataclass
class ScopeRule:
    """A single scope rule."""
    scope_type: ScopeType
    value: str
    description: str = ""
    allowed_ports: Optional[Set[int]] = None
    allowed_protocols: Optional[Set[str]] = None

    def matches(self, target: str) -> bool:
        """Check if target matches this scope rule."""
        if self.scope_type == ScopeType.IP_RANGE:
            return self._match_ip_range(target)
        elif self.scope_type == ScopeType.DOMAIN:
            return self._match_domain(target)
        elif self.scope_type == ScopeType.URL:
            return self._match_url(target)
        elif self.scope_type == ScopeType.CIDR:
            return self._match_cidr(target)
        elif self.scope_type == ScopeType.NETWORK:
            return self._match_network(target)
        return False

    def _match_ip_range(self, target: str) -> bool:
        """Match IP address or range."""
        try:
            import ipaddress
            # Handle CIDR notation
            if '/' in self.value:
                network = ipaddress.ip_network(self.value, strict=False)
                target_ip = ipaddress.ip_address(target)
                return target_ip in network
            # Handle range notation (e.g., 192.168.1.1-192.168.1.254)
            elif '-' in self.value:
                start, end = self.value.split('-')
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                target_ip = ipaddress.ip_address(target)
                return start_ip <= target_ip <= end_ip
            else:
                # Single IP
                return target == self.value
        except Exception:
            return False

    def _match_domain(self, target: str) -> bool:
        """Match domain or subdomain."""
        target_lower = target.lower()
        scope_lower = self.value.lower()
        # Exact match or subdomain
        return target_lower == scope_lower or target_lower.endswith('.' + scope_lower)

    def _match_url(self, target: str) -> bool:
        """Match URL."""
        try:
            parsed = urlparse(target)
            host = parsed.netloc
            # Remove port if present
            if ':' in host:
                host = host.split(':')[0]
            return self._match_domain(host)
        except Exception:
            return False

    def _match_cidr(self, target: str) -> bool:
        """Match CIDR notation."""
        return self._match_ip_range(target)

    def _match_network(self, target: str) -> bool:
        """Match network range."""
        return self._match_ip_range(target)


@dataclass
class Scope:
    """Security assessment scope definition."""
    target: str
    rules: List[ScopeRule] = field(default_factory=list)
    description: str = ""
    authorization_ref: str = ""
    max_risk_level: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    allowed_actions: List[str] = field(default_factory=list)
    denied_actions: List[str] = field(default_factory=list)
    time_limit_minutes: int = 60
    max_concurrent_tools: int = 3

    def __post_init__(self):
        """Validate scope on creation."""
        if not self.rules and self.target:
            # Auto-create rule from target
            self.rules.append(self._auto_create_rule(self.target))

    def _auto_create_rule(self, target: str) -> ScopeRule:
        """Auto-detect scope type from target."""
        # Check if IP
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        ip_range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$'
        url_pattern = r'^https?://'
        domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        if re.match(url_pattern, target):
            parsed = urlparse(target)
            host = parsed.netloc
            if ':' in host:
                host = host.split(':')[0]
            return ScopeRule(ScopeType.DOMAIN, host, f"Auto-detected from URL: {target}")
        elif re.match(ip_pattern, target) or re.match(ip_range_pattern, target):
            return ScopeRule(ScopeType.CIDR, target, f"Auto-detected IP/CIDR: {target}")
        elif re.match(domain_pattern, target):
            return ScopeRule(ScopeType.DOMAIN, target, f"Auto-detected domain: {target}")
        else:
            return ScopeRule(ScopeType.DOMAIN, target, f"Default scope: {target}")

    def is_in_scope(self, target: str) -> bool:
        """Check if target is within scope."""
        for rule in self.rules:
            if rule.matches(target):
                return True
        return False

    def is_action_allowed(self, action: str) -> bool:
        """Check if action is allowed."""
        if self.denied_actions and action in self.denied_actions:
            return False
        if self.allowed_actions and action not in self.allowed_actions:
            return False
        return True

    def validate_target(self, target: str) -> bool:
        """Validate target is in scope, raise if not."""
        if not self.is_in_scope(target):
            raise ScopeViolation(
                f"Target '{target}' is outside declared scope. "
                f"Allowed: {[str(r.value) for r in self.rules]}"
            )
        return True

    def get_allowed_ports(self, target: str) -> Optional[Set[int]]:
        """Get allowed ports for target."""
        for rule in self.rules:
            if rule.matches(target) and rule.allowed_ports:
                return rule.allowed_ports
        return None

    def get_allowed_protocols(self, target: str) -> Optional[Set[str]]:
        """Get allowed protocols for target."""
        for rule in self.rules:
            if rule.matches(target) and rule.allowed_protocols:
                return rule.allowed_protocols
        return None


class ScopeEnforcer:
    """Enforces scope boundaries during agent execution."""

    def __init__(self, scope: Scope):
        self.scope = scope
        self.violations: List[ScopeViolation] = []

    def check_target(self, target: str) -> bool:
        """Check if target is in scope."""
        return self.scope.is_in_scope(target)

    def enforce_target(self, target: str) -> bool:
        """Enforce target is in scope, raise if not."""
        if not self.scope.is_in_scope(target):
            violation = ScopeViolation(
                f"Target '{target}' is outside declared scope. "
                f"Allowed: {[str(r.value) for r in self.scope.rules]}"
            )
            self.violations.append(violation)
            logger.error(f"Scope violation: {violation}")
            raise violation
        return True

    def check_action(self, action: str) -> bool:
        """Check if action is allowed."""
        return self.scope.is_action_allowed(action)

    def enforce_action(self, action: str) -> bool:
        """Enforce action is allowed, raise if not."""
        if not self.scope.is_action_allowed(action):
            violation = ScopeViolation(
                f"Action '{action}' is not allowed within scope. "
                f"Allowed: {self.scope.allowed_actions}, Denied: {self.scope.denied_actions}"
            )
            self.violations.append(violation)
            logger.error(f"Scope violation: {violation}")
            raise violation
        return True

    def get_violations(self) -> List[ScopeViolation]:
        """Get all recorded violations."""
        return self.violations


def parse_scope_declaration(declaration: str) -> Scope:
    """Parse a scope declaration string into a Scope object.

    Format examples:
    - "192.168.1.0/24"
    - "example.com"
    - "https://api.example.com"
    - "192.168.1.1-192.168.1.254"
    - "192.168.1.0/24, example.com, https://api.example.com"
    """
    targets = [t.strip() for t in declaration.split(',')]
    rules = []

    for target in targets:
        if not target:
            continue
        scope = Scope(target=target)  # This auto-creates rule
        rules.extend(scope.rules)

    # Use first target as primary
    primary_target = targets[0] if targets else ""
    return Scope(
        target=targets[0] if targets else "",
        rules=rules,
        description=f"Parsed from: {declaration}"
    )


def validate_authorization(scope, auth_token=None) -> bool:
    """Validate authorization for scope."""
    # Accept token from scope reference or direct token
    if not scope.authorization_ref and not auth_token:
        logger.warning("No authorization reference in scope or token provided")
        return False

    # In production, validate against authorization system
    # For now, check if token is provided (either in scope or directly)
    if scope.authorization_ref or auth_token:
        logger.info(f"Authorization validated for scope: {scope.target}")
        return True

    logger.warning("No authorization token provided")
    return False