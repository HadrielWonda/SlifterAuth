using Microsoft.AspNetCore.Authorization;

namespace SlifterAuth.Authorization;


public class AuthorizeView : AuthorizeViewCore
{
    private readonly IAuthorizeData[] selfAsAuthorizeData;

    
    public AuthorizeView()
    {
        selfAsAuthorizeData = new[] { new AuthorizeDataAdapter(this) };
    }

    
    [Parameter] public string? Policy { get; set; }

   
    [Parameter] public string? Roles { get; set; }

    
    protected override IAuthorizeData[] GetAuthorizeData()
        => selfAsAuthorizeData;
}
