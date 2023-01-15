using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Rendering;

namespace SlifterAuth.Authorization;


public abstract class AuthorizeViewCore : ComponentBase
{
    private AuthenticationState? currentAuthenticationState;
    private bool? isAuthorized;

   
    [Parameter] public RenderFragment<AuthenticationState>? ChildContent { get; set; }

  
    [Parameter] public RenderFragment<AuthenticationState>? NotAuthorized { get; set; }

    
    [Parameter] public RenderFragment<AuthenticationState>? Authorized { get; set; }

    
    [Parameter] public RenderFragment? Authorizing { get; set; }

   
    [Parameter] public object? Resource { get; set; }

    [CascadingParameter] private Task<AuthenticationState>? AuthenticationState { get; set; }

    [Inject] private IAuthorizationPolicyProvider AuthorizationPolicyProvider { get; set; } = default!;

    [Inject] private IAuthorizationService AuthorizationService { get; set; } = default!;

    
    protected override void BuildRenderTree(RenderTreeBuilder builder)
    {
       
        if (isAuthorized == null)
        {
            builder.AddContent(0, Authorizing);
        }
        else if (isAuthorized == true)
        {
            var authorized = Authorized ?? ChildContent;
            builder.AddContent(0, authorized?.Invoke(currentAuthenticationState!));
        }
        else
        {
            builder.AddContent(0, NotAuthorized?.Invoke(currentAuthenticationState!));
        }
    }

    protected override async Task OnParametersSetAsync()
    {
       
        if (ChildContent != null && Authorized != null)
        {
            throw new InvalidOperationException($"Do not specify both '{nameof(Authorized)}' and '{nameof(ChildContent)}'.");
        }

        if (AuthenticationState == null)
        {
            throw new InvalidOperationException($"Authorization requires a cascading parameter of type Task<{nameof(AuthenticationState)}>.
            Consider using {typeof(CascadingAuthenticationState).
            Name
            } to supply this.");
        }

       

        currentAuthenticationState = await AuthenticationState;
        isAuthorized = await IsAuthorizedAsync(currentAuthenticationState.User);
    }

    
    protected abstract IAuthorizeData[]? GetAuthorizeData();

    private async Task<bool> IsAuthorizedAsync(ClaimsPrincipal user)
    {
        var authorizeData = GetAuthorizeData();
        if (authorizeData == null)
        {
            
            return true;
        }

        EnsureNoAuthenticationSchemeSpecified(authorizeData);

        var policy = await AuthorizationPolicy.CombineAsync(
            AuthorizationPolicyProvider, authorizeData);
        var result = await AuthorizationService.AuthorizeAsync(user, Resource, policy!);
        return result.Succeeded;
    }

    private static void EnsureNoAuthenticationSchemeSpecified(IAuthorizeData[] authorizeData)
    {
        
        for (var i = 0; i < authorizeData.Length; i++)
        {
            var entry = authorizeData[i];
            if (!string.IsNullOrEmpty(entry.AuthenticationSchemes))
            {
                throw new NotSupportedException($"The authorization data specifies an authentication scheme with value '{entry.AuthenticationSchemes}'.
                Authentication schemes cannot be specified for components."
                );
            }
        }
    }
}
