using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

[Route("api/pages")]
[ApiController]
[Authorize(Roles = "Admin")]
public class PageApiController : ControllerBase
{
    private readonly PageDiscoveryService _pageDiscoveryService;

    public PageApiController(PageDiscoveryService pageDiscoveryService)
    {
        _pageDiscoveryService = pageDiscoveryService;
    }

    [HttpGet]
    public IActionResult GetPages()
    {
        List<string> pages = _pageDiscoveryService.GetAllPages();
        return Ok(pages);
    }
}
