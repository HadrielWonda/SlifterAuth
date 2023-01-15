

namespace SlifterAuth.Authorization;


public abstract class AuthenticationStateProvider
{
    public abstract Task<AuthenticationState> GetAuthenticationStateAsync();

   
    public event AuthenticationStateChangedHandler? AuthenticationStateChanged;

  
    
  
    protected void NotifyAuthenticationStateChanged(Task<AuthenticationState> task)
    {
        ArgumentNullException.ThrowIfNull(task);

        AuthenticationStateChanged?.Invoke(task);
    }
}


public delegate void AuthenticationStateChangedHandler(Task<AuthenticationState> task);
