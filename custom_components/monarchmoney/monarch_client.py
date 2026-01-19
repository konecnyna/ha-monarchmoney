"""Monarch Money client with updated API endpoint.

Monarch has migrated their API from api.monarchmoney.com to api.monarch.com.
This module patches the MonarchMoney library to use the new endpoint.
"""

import logging
from monarchmoney import MonarchMoney as OriginalMonarchMoney

_LOGGER = logging.getLogger(__name__)

# Monarch has migrated their API from api.monarchmoney.com to api.monarch.com
NEW_BASE_URL = "https://api.monarch.com"

# Monkey patch the MonarchMoneyEndpoints class to use the new base URL
try:
    from monarchmoney.monarchmoney import MonarchMoneyEndpoints

    # Store original methods
    _original_getLoginEndpoint = MonarchMoneyEndpoints.getLoginEndpoint
    _original_getGraphQL = MonarchMoneyEndpoints.getGraphQL
    _original_getAccountBalanceHistoryUploadEndpoint = (
        MonarchMoneyEndpoints.getAccountBalanceHistoryUploadEndpoint
    )

    # Override the BASE_URL
    MonarchMoneyEndpoints.BASE_URL = NEW_BASE_URL

    # Override the methods to use the new base URL
    @classmethod
    def _patched_getLoginEndpoint(cls) -> str:
        return cls.BASE_URL + "/auth/login/"

    @classmethod
    def _patched_getGraphQL(cls) -> str:
        return cls.BASE_URL + "/graphql"

    @classmethod
    def _patched_getAccountBalanceHistoryUploadEndpoint(cls) -> str:
        return cls.BASE_URL + "/account-balance-history/upload/"

    MonarchMoneyEndpoints.getLoginEndpoint = _patched_getLoginEndpoint
    MonarchMoneyEndpoints.getGraphQL = _patched_getGraphQL
    MonarchMoneyEndpoints.getAccountBalanceHistoryUploadEndpoint = (
        _patched_getAccountBalanceHistoryUploadEndpoint
    )

    _LOGGER.info(f"Patched MonarchMoney API endpoint to use {NEW_BASE_URL}")

except ImportError:
    _LOGGER.warning(
        "Could not import MonarchMoneyEndpoints - endpoint patching may not work"
    )


class MonarchMoney(OriginalMonarchMoney):
    """Wrapper for MonarchMoney that uses the new API endpoint.

    This class inherits from the original MonarchMoney class but patches
    the endpoints to use api.monarch.com instead of api.monarchmoney.com.
    """

    pass  # The patching is done at the module level above
