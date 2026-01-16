"""Cloudflare bypass implementation using cloudscraper for advanced Cloudflare protection."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional
from functools import partial

import cloudscraper
from monarchmoney import LoginFailedException, RequireMFAException

_LOGGER = logging.getLogger(__name__)


class CloudflareBypassMonarchMoney:
    """
    MonarchMoney client that uses cloudscraper to bypass Cloudflare's protection.

    cloudscraper automatically solves Cloudflare JS challenges and uses browser-like
    headers to avoid detection.
    """

    def __init__(self, session_file: str = "~/.monarchmoney/session.pkl", timeout: int = 10):
        """Initialize the Cloudflare bypass client."""
        self._session_file = session_file
        self._timeout = timeout
        self._token: Optional[str] = None

        # Create cloudscraper session with browser-like settings
        self._scraper = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'darwin',
                'desktop': True
            },
            delay=10  # Delay for solving Cloudflare challenges
        )

        self._headers = {
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Client-Platform": "web",
            "Content-Type": "application/json",
            "Origin": "https://app.monarchmoney.com",
            "Referer": "https://app.monarchmoney.com/",
        }

        self._graphql_url = "https://api.monarchmoney.com/graphql"
        self._login_url = "https://api.monarchmoney.com/auth/login/"

    async def login(
        self,
        email: str,
        password: str,
        save_session: bool = True,
        use_saved_session: bool = True,
        mfa_secret_key: Optional[str] = None,
    ) -> None:
        """
        Authenticate with Monarch Money using cloudscraper to bypass Cloudflare.

        Args:
            email: User email address
            password: User password
            save_session: Whether to save the session (not implemented yet)
            use_saved_session: Whether to use saved session (not implemented yet)
            mfa_secret_key: Optional MFA TOTP secret for automatic MFA
        """
        _LOGGER.debug("Attempting login with cloudscraper")

        # Prepare login payload
        login_data = {
            "email": email,
            "password": password,
            "trusted_device": False,
        }

        # If MFA secret is provided, generate TOTP code
        if mfa_secret_key:
            import pyotp
            totp = pyotp.TOTP(mfa_secret_key)
            login_data["totp"] = totp.now()
            _LOGGER.debug("Including TOTP code in login request")

        try:
            # Run blocking requests in executor to avoid blocking event loop
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                partial(
                    self._scraper.post,
                    self._login_url,
                    json=login_data,
                    headers=self._headers,
                    timeout=self._timeout
                )
            )

            _LOGGER.debug(f"Login response status: {response.status_code}")

            if response.status_code == 403:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get("errorMessage", "")

                if "MFA" in error_msg or "multi-factor" in error_msg.lower():
                    _LOGGER.error("MFA required but not properly handled")
                    raise RequireMFAException("Multi-Factor Auth Required")

                raise LoginFailedException(f"Login failed: {error_msg}")

            if response.status_code == 429:
                raise LoginFailedException("Rate limited by Monarch Money API")

            if response.status_code == 525:
                _LOGGER.error("Received 525 SSL handshake error - Cloudflare protection may be too strict")
                raise LoginFailedException(
                    "SSL handshake failed with Cloudflare. This may indicate very strict protection. "
                    "Response text: " + response.text[:500]
                )

            if response.status_code != 200:
                error_text = response.text if response.content else "Unknown error"
                _LOGGER.error(f"Login failed with status {response.status_code}: {error_text[:200]}")
                raise LoginFailedException(f"Login failed with status {response.status_code}: {error_text[:200]}")

            # Extract token from response
            response_data = response.json()
            self._token = response_data.get("token")

            if not self._token:
                raise LoginFailedException("No token received from login response")

            # Update headers with auth token
            self._headers["Authorization"] = f"Token {self._token}"
            self._scraper.headers.update(self._headers)
            _LOGGER.info("Successfully logged in with cloudscraper bypass")

        except RequireMFAException:
            raise
        except Exception as e:
            _LOGGER.error(f"Login failed with cloudscraper: {e}")
            raise LoginFailedException(f"Login error: {str(e)}") from e

    async def multi_factor_authenticate(
        self, email: str, password: str, code: str
    ) -> None:
        """
        Perform multi-factor authentication with a one-time code.

        Args:
            email: User email address
            password: User password
            code: MFA one-time code
        """
        _LOGGER.debug("Attempting MFA authentication with cloudscraper")

        mfa_data = {
            "email": email,
            "password": password,
            "totp": code,
            "trusted_device": False,
        }

        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                partial(
                    self._scraper.post,
                    self._login_url,
                    json=mfa_data,
                    headers=self._headers,
                    timeout=self._timeout
                )
            )

            _LOGGER.debug(f"MFA response status: {response.status_code}")

            if response.status_code == 429:
                raise LoginFailedException("Rate limited by Monarch Money API")

            if response.status_code == 525:
                _LOGGER.error("Received 525 SSL handshake error during MFA")
                raise LoginFailedException("SSL handshake failed with Cloudflare during MFA")

            if response.status_code != 200:
                error_text = response.text if response.content else "Unknown error"
                raise LoginFailedException(f"MFA authentication failed: {error_text[:200]}")

            # Extract token from response
            response_data = response.json()
            self._token = response_data.get("token")

            if not self._token:
                raise LoginFailedException("No token received from MFA response")

            # Update headers with auth token
            self._headers["Authorization"] = f"Token {self._token}"
            self._scraper.headers.update(self._headers)
            _LOGGER.info("Successfully authenticated with MFA using cloudscraper")

        except Exception as e:
            _LOGGER.error(f"MFA authentication failed: {e}")
            raise LoginFailedException(f"MFA error: {str(e)}") from e

    async def _graphql_query(self, query: str, variables: Optional[dict] = None) -> dict[str, Any]:
        """
        Execute a GraphQL query using cloudscraper.

        Args:
            query: GraphQL query string
            variables: Optional variables for the query

        Returns:
            Query response data
        """
        if not self._token:
            raise LoginFailedException("Not authenticated - no token available")

        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                partial(
                    self._scraper.post,
                    self._graphql_url,
                    json=payload,
                    headers=self._headers,
                    timeout=self._timeout
                )
            )

            if response.status_code == 401:
                raise LoginFailedException("Authentication expired or invalid")

            if response.status_code == 525:
                _LOGGER.error("Received 525 SSL handshake error during GraphQL query")
                raise LoginFailedException("SSL handshake failed with Cloudflare during query")

            if response.status_code != 200:
                error_text = response.text if response.content else "Unknown error"
                raise LoginFailedException(f"GraphQL query failed: {error_text[:200]}")

            response_data = response.json()

            if "errors" in response_data:
                error_msg = response_data["errors"]
                _LOGGER.error(f"GraphQL errors: {error_msg}")
                raise LoginFailedException(f"GraphQL error: {error_msg}")

            return response_data.get("data", {})

        except Exception as e:
            _LOGGER.error(f"GraphQL query failed: {e}")
            raise

    async def get_accounts(self) -> dict[str, Any]:
        """Get all accounts from Monarch Money."""
        query = """
        query GetAccounts {
            accounts {
                id
                displayName
                syncDisabled
                deactivatedAt
                isHidden
                isAsset
                mask
                createdAt
                updatedAt
                displayLastUpdatedAt
                currentBalance
                displayBalance
                includeInNetWorth
                hideFromList
                hideTransactionsFromReports
                includeBalanceInNetWorth
                includeInGoalBalance
                dataProvider
                dataProviderAccountId
                isManual
                transactionsCount
                holdingsCount
                manualInvestmentsTrackingMethod
                order
                icon
                logoUrl
                type {
                    name
                    display
                }
                subtype {
                    name
                    display
                }
                credential {
                    id
                    updateRequired
                    dataProvider
                    disconnectedFromDataProviderAt
                }
            }
        }
        """

        _LOGGER.debug("Fetching accounts with cloudscraper")
        data = await self._graphql_query(query)
        return {"accounts": data.get("accounts", [])}

    async def get_transaction_categories(self) -> dict[str, Any]:
        """Get all transaction categories from Monarch Money."""
        query = """
        query GetTransactionCategories {
            categories {
                id
                name
                icon
                order
                systemCategory
                isSystemCategory
                isDisabled
                group {
                    id
                    name
                    type
                }
            }
        }
        """

        _LOGGER.debug("Fetching categories with cloudscraper")
        data = await self._graphql_query(query)
        return {"categories": data.get("categories", [])}

    async def get_cashflow(self) -> dict[str, Any]:
        """Get cashflow summary from Monarch Money."""
        query = """
        query GetCashFlowSummary {
            cashFlowSummary {
                sumIncome
                sumExpense
            }
        }
        """

        _LOGGER.debug("Fetching cashflow with cloudscraper")
        data = await self._graphql_query(query)
        return data.get("cashFlowSummary", {})

    async def get_subscription_details(self) -> dict[str, Any]:
        """Get subscription details (used for session validation)."""
        query = """
        query GetSubscriptionDetails {
            subscription {
                id
                isActive
            }
        }
        """

        _LOGGER.debug("Fetching subscription details with cloudscraper")
        data = await self._graphql_query(query)
        return data.get("subscription", {})

    def load_session(self) -> None:
        """Load a saved session (stub - not implemented yet)."""
        _LOGGER.warning("load_session is not yet implemented in CloudflareBypassMonarchMoney")
        pass

    def save_session(self) -> None:
        """Save the current session (stub - not implemented yet)."""
        _LOGGER.warning("save_session is not yet implemented in CloudflareBypassMonarchMoney")
        pass
