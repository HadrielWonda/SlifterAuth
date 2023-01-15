

using System.Security.Claims;

namespace Microsoft.AspNetCore.Components.Authorization;


public class AuthenticationState
{
    
    
    public AuthenticationState(ClaimsPrincipal user)
    {
        User = user ?? throw new ArgumentNullException(nameof(user));
    }

    
    public ClaimsPrincipal User { get; }
}
