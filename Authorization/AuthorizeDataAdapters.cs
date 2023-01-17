using System;

namespace SlifterAuth.Authorization;


internal sealed class AuthorizeDataAdapter : IAuthorizeData
{
    private readonly AuthorizeView _component;

    public AuthorizeDataAdapter(AuthorizeView component)
    {
        _component = component ?? throw new ArgumentNullException(nameof(component));
    }

    public string? Policy
    {
        get => _component.Policy;
        set => throw new NotSupportedException();
    }

    public string? Roles
    {
        get => _component.Roles;
        set => throw new NotSupportedException();
    }

  
    public string? AuthenticationSchemes
    {
        get => null;
        set => throw new NotSupportedException();
    }
}
