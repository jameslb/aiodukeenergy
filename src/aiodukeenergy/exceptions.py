"""Exceptions for Duke Energy API client."""


class DukeEnergyError(Exception):
    """Base exception for Duke Energy API errors."""


class DukeEnergyAuthError(DukeEnergyError):
    """Exception raised when authentication fails."""


class DukeEnergyBlockedError(DukeEnergyError):
    """Exception raised when Duke's edge rejects a request before authentication."""


class DukeEnergyOAuthCallbackError(DukeEnergyAuthError):
    """Exception raised when Auth0 returns an OAuth error callback."""

    def __init__(self, error: str, description: str | None = None) -> None:
        """Initialize an OAuth callback error."""
        self.error = error
        self.description = description
        super().__init__(f"{error}: {description}" if description else error)


class DukeEnergyTokenExpiredError(DukeEnergyAuthError):
    """Exception raised when the access token has expired."""
