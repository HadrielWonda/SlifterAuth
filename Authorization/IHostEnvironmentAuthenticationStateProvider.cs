namespace Microsoft.AspNetCore.Components.Authorization;


public interface IHostEnvironmentAuthenticationStateProvider
{
    void SetAuthenticationState(Task<AuthenticationState> authenticationStateTask);
}
