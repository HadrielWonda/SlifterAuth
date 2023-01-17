namespace SlifterAuth.Authentication.JwtBearer;


public class JwtBearerEvents
{
    public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

    public Func<ForbiddenContext, Task> OnForbidden { get; set; } = context => Task.CompletedTask;
    
    public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.CompletedTask;

    public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = context => Task.CompletedTask;
   
    public Func<JwtBearerChallengeContext, Task> OnChallenge { get; set; } = context => Task.CompletedTask;

    public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

    public virtual Task Forbidden(ForbiddenContext context) => OnForbidden(context);

    public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);

    public virtual Task TokenValidated(TokenValidatedContext context) => OnTokenValidated(context);

    public virtual Task Challenge(JwtBearerChallengeContext context) => OnChallenge(context);
}
