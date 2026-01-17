"""Custom SSL adapter for improved Cloudflare compatibility.

This module provides a custom SSL/TLS context configuration to resolve
HTTP 525 SSL handshake failures when connecting to Monarch Money API
through Cloudflare protection.
"""

import logging
import ssl
from typing import Any

from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

_LOGGER = logging.getLogger(__name__)


class SSLAdapter(HTTPAdapter):
    """HTTPAdapter with custom SSL context for Cloudflare compatibility.

    This adapter uses a relaxed cipher suite configuration to ensure
    compatibility with Monarch Money's origin servers while maintaining
    reasonable security standards.
    """

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        """Initialize pool manager with custom SSL context."""
        # Create custom SSL context with broader cipher support
        ssl_context = create_custom_ssl_context()
        kwargs["ssl_context"] = ssl_context
        _LOGGER.debug("Initializing pool manager with custom SSL context")
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy: Any, **proxy_kwargs: Any) -> Any:
        """Initialize proxy manager with custom SSL context."""
        ssl_context = create_custom_ssl_context()
        proxy_kwargs["ssl_context"] = ssl_context
        _LOGGER.debug("Initializing proxy manager with custom SSL context")
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def create_custom_ssl_context() -> ssl.SSLContext:
    """Create a custom SSL context with relaxed cipher suites.

    This context enables TLS 1.2 and 1.3 with a broader set of cipher suites
    to ensure compatibility with Cloudflare-protected endpoints.

    For Python 3.13+ with OpenSSL 3.5+, uses aggressive compatibility settings.

    Returns:
        ssl.SSLContext: Configured SSL context for use with urllib3
    """
    _LOGGER.info("Creating custom SSL context for Cloudflare compatibility")

    # Start with urllib3's default context (based on Python's ssl.create_default_context)
    context = create_urllib3_context()

    # Enable TLS 1.2 and 1.3
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        _LOGGER.info("Set TLS version range: 1.2 to 1.3")
    except AttributeError:
        # Fallback for older Python versions
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        _LOGGER.info("Using legacy TLS configuration (Python < 3.7)")

    # For OpenSSL 3.x, use SECLEVEL=1 to allow broader cipher compatibility
    # SECLEVEL=1: 112-bit security level, allows RSA/DH keys >= 2048 bits
    # This is more permissive than the OpenSSL 3.x default of SECLEVEL=2
    cipher_list = (
        # Use all available ciphers with security level 1 (more permissive for compatibility)
        "DEFAULT@SECLEVEL=1:"
        # Explicitly include modern ciphers
        "ECDHE+AESGCM:ECDHE+CHACHA20:"
        "DHE+AESGCM:DHE+CHACHA20:"
        "ECDHE+AES:RSA+AESGCM:RSA+AES:"
        # Exclusions - only exclude truly insecure ciphers
        "!aNULL:!eNULL:!EXPORT:!MD5:!PSK:!SRP:!CAMELLIA"
    )

    try:
        context.set_ciphers(cipher_list)
        _LOGGER.info("Applied aggressive cipher list with SECLEVEL=1 for Cloudflare compatibility")
    except ssl.SSLError as e:
        _LOGGER.warning(f"Failed to set custom cipher list: {e}")
        # Fallback: try even more permissive
        try:
            context.set_ciphers("DEFAULT@SECLEVEL=0")
            _LOGGER.warning("Fell back to SECLEVEL=0 (maximum compatibility, reduced security)")
        except ssl.SSLError as e2:
            _LOGGER.error(f"Failed to set fallback cipher list: {e2}, using system defaults")

    # Disable strict hostname checking that might interfere (but keep certificate validation)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    # Log SSL configuration details
    _LOGGER.info(
        f"SSL Context configured - "
        f"OpenSSL: {ssl.OPENSSL_VERSION}, "
        f"Check hostname: {context.check_hostname}, "
        f"Verify mode: {context.verify_mode}"
    )

    return context


def create_ssl_adapter() -> SSLAdapter:
    """Create and return an SSLAdapter instance.

    Returns:
        SSLAdapter: Configured adapter ready to mount on a session
    """
    return SSLAdapter()


def apply_ssl_adapter(session: Any) -> None:
    """Apply custom SSL adapter to an existing requests session.

    Args:
        session: A requests.Session or cloudscraper session to configure
    """
    adapter = create_ssl_adapter()
    session.mount('https://', adapter)
    _LOGGER.info("Applied custom SSL adapter for improved Cloudflare compatibility")
