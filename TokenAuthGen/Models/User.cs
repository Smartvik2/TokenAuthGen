using Microsoft.AspNetCore.Identity;

namespace TokenAuthGen.Models
{
    public class User : IdentityUser
    {
       
        public bool IsConfirmed { get; set; } = false;
        public string? EmailConfirmationToken { get; set; }

    }
}
