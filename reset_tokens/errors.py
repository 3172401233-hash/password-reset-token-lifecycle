class TokenError(Exception):
    """Base class for every token lifecycle failure."""


class TokenInvalidError(TokenError):
    """The token is malformed, has a bad signature or is unknown."""


class TokenExpiredError(TokenError):
    """The token was valid once but its time-to-live has elapsed."""


class TokenConsumedError(TokenError):
    """The token has already been redeemed in a prior request."""


class TokenRevokedError(TokenError):
    """The token was revoked before it could be consumed."""


class TokenBindingError(TokenError):
    """The token does not match the user, email or purpose presented."""


class StoreUnavailableError(TokenError):
    """The backing database failed even after retrying."""
