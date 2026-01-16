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
        return super().init_poolmanager(*args, **kwargs)


def create_custom_ssl_context() -> ssl.SSLContext:
    """Create a custom SSL context with relaxed cipher suites.

    This context enables TLS 1.2 and 1.3 with a broader set of cipher suites
    to ensure compatibility with Cloudflare-protected endpoints.

    Returns:
        ssl.SSLContext: Configured SSL context for use with urllib3
    """
    # Start with urllib3's default context (based on Python's ssl.create_default_context)
    context = create_urllib3_context()

    # Enable TLS 1.2 and 1.3
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        _LOGGER.debug("Set TLS version range: 1.2 to 1.3")
    except AttributeError:
        # Fallback for older Python versions
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        _LOGGER.debug("Using legacy TLS configuration (Python < 3.7)")

    # Expanded cipher list for broader compatibility
    # Still excludes weak ciphers (aNULL, eNULL, EXPORT, DES, MD5, PSK, RC4)
    cipher_list = (
        # Modern ECDHE with AEAD ciphers (preferred)
        "ECDHE+AESGCM:ECDHE+CHACHA20:"
        # DHE with AEAD ciphers
        "DHE+AESGCM:DHE+CHACHA20:"
        # ECDHE with CBC mode AES (broader compatibility)
        "ECDHE+AES:"
        # RSA key exchange with AEAD (for maximum compatibility)
        "RSA+AESGCM:RSA+AES:"
        # Exclusions - no anonymous, no export, no weak algorithms
        "!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:!3DES"
    )

    try:
        context.set_ciphers(cipher_list)
        _LOGGER.debug(f"Applied custom cipher list for Cloudflare compatibility")
    except ssl.SSLError as e:
        _LOGGER.warning(f"Failed to set custom cipher list: {e}, using defaults")

    # Log SSL configuration details
    _LOGGER.debug(
        f"SSL Context configured - "
        f"Protocol: {getattr(ssl, 'OPENSSL_VERSION', 'unknown')}, "
        f"Python SSL: {ssl.OPENSSL_VERSION if hasattr(ssl, 'OPENSSL_VERSION') else 'unknown'}"
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
