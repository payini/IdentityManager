using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace IdentityManager
{
    public class ApplicationUser : IdentityUser
    {
        public virtual ICollection<IdentityUserRole<string>>? Roles { get; set; }
        public virtual ICollection<IdentityUserClaim<string>>? Claims { get; set; }
    }
}