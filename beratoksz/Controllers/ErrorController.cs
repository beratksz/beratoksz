﻿using System.Diagnostics;
using beratoksz.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace beratoksz.Controllers
{
    [AllowAnonymous]
    public class ErrorController : Controller
    {
        [HttpGet("Error/{statusCode}")]
        public IActionResult HandleError(int statusCode)
        {
            switch (statusCode)
            {
                case 403:
                    return View("AccessDenied");
                case 404:
                    return View("NotFound");
                case 429:
                    return View("TooManyRequests");
                default:
                    return View("Error");
            }
        }

    }
}
