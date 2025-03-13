using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;

namespace beratoksz.Controllers.Api
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // Bu attribute sayesinde, geçerli bir JWT token gerektirecek
    public class ExampleController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok(new
            {
                Message = "Bu korumalı API çağrısı başarılı.",
                Time = DateTime.UtcNow
            });
        }
    }
}
