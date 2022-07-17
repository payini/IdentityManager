using System.ComponentModel.DataAnnotations;

namespace IdentityManagerBlazorServer.ViewModels
{
    public class RoleViewModel
    {
        [Required]
        public string? Name { get; set; }
    }
}
