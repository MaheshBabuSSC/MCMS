using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace MCMS.Controllers
{
    public class BaseController : Controller
    {
        protected string GetCurrentUserId()
        {
            return User.FindFirstValue("UserId") ?? "0";
        }

        protected string GetCurrentRoleId()
        {
            return User.FindFirstValue("RoleId") ?? "0";
        }

        protected string GetCurrentRoleName()
        {
            return User.FindFirstValue("RoleName") ?? "User";
        }

        protected string GetCurrentUserName()
        {
            return User.Identity?.Name ?? "User";
        }
    }
}
