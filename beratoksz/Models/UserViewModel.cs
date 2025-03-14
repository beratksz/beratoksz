using System;
using System.Collections.Generic;

namespace beratoksz.Models
{
    public class UserViewModel
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public IList<string> Roles { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
