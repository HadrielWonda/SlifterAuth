

using System.Collections.Concurrent;


namespace SlifterAuth.Authorization;

internal static class AttributeAuthorizeDataCache
{
    private static readonly ConcurrentDictionary<Type, IAuthorizeData[]?> _cache = new();

    public static IAuthorizeData[]? GetAuthorizeDataForType(Type type)
    {
        if (!_cache.TryGetValue(type, out var result))
        {
            result = ComputeAuthorizeDataForType(type);
            _cache[type] = result; 
        }

        return result;
    }

    private static IAuthorizeData[]? ComputeAuthorizeDataForType(Type type)
    {
        
        var allAttributes = type.GetCustomAttributes(inherit: true);
        List<IAuthorizeData>? authorizeDatas = null;
        for (var i = 0; i < allAttributes.Length; i++)
        {
            if (allAttributes[i] is IAllowAnonymous)
            {
                return null;
            }

            if (allAttributes[i] is IAuthorizeData authorizeData)
            {
                authorizeDatas ??= new();
                authorizeDatas.Add(authorizeData);
            }
        }

        return authorizeDatas?.ToArray();
    }
}
