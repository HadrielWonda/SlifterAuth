namespace SlifterAuth.Authentication.JwtBearer;

internal static class AuthenticateResults
{
    internal static AuthenticateResult ValidatorNotFound = AuthenticateResult.Fail("No SecurityTokenValidator available for token.");
}
