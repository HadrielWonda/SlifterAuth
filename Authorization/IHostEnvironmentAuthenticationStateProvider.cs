namespace SlifterAuth.Authorization;


public interface IHostEnvironmentAuthenticationStateProvider
{
    void SetAuthenticationState(Task<AuthenticationState> authenticationStateTask);
}
