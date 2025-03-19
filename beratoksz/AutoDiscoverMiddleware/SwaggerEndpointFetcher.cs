using Microsoft.AspNetCore.Mvc.ApiExplorer;
using static PageDiscoveryService;

public class SwaggerEndpointFetcher
{
    private readonly IApiDescriptionGroupCollectionProvider _apiExplorer;

    public SwaggerEndpointFetcher(IApiDescriptionGroupCollectionProvider apiExplorer)
    {
        _apiExplorer = apiExplorer;
    }

    public List<string> GetEndpoints()
    {
        var endpoints = _apiExplorer.ApiDescriptionGroups.Items
            .SelectMany(g => g.Items)
            .Select(d => UrlNormalizer.Normalize(d.RelativePath))
            .Distinct()
            .ToList();

        return endpoints;
    }
}
