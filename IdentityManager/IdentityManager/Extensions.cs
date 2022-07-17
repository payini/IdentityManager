using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace IdentityManager
{
    public static class Extensions
    {
        public static string GetAllMessages(this IEnumerable<IdentityError> errors)
        {
            var result = string.Empty;

            foreach (var error in errors)
            {
                result += string.IsNullOrEmpty(result) ? string.Empty : " ";
                result += error.Description;
            }

            return result;
        }
    }
}