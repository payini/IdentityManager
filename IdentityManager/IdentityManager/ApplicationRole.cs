using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace IdentityManager
{
    public class ApplicationRole : IdentityRole
    {
        public ApplicationRole() { }

        public ApplicationRole(string roleName) : base(roleName) { }

        public virtual ICollection<IdentityRoleClaim<string>>? Claims { get; set; }
    }
}