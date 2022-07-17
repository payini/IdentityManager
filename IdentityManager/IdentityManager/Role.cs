using System.Collections.Generic;

namespace IdentityManager
{
    public class Role
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
        public IEnumerable<KeyValuePair<string, string>>? Claims { get; set; }
    }
}