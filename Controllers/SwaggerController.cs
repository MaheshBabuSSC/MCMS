using CMS.Models;
using CMS.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Npgsql;
using Dapper;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;
using System.Security.Cryptography;

namespace CMS.Controllers
{
    [Route("api")]
    [ApiController] // This ensures it appears in Swagger
    public class SwaggerController : ControllerBase
    {
        private readonly IAdminService _adminService;
        private readonly AuthService _authService;
        private readonly ILogger<SwaggerController> _logger;
        private readonly EmailService _emailService;
        private readonly IConfiguration _configuration;

        public SwaggerController(
            IAdminService adminService,
            AuthService authService,
            ILogger<SwaggerController> logger,
            EmailService emailService,
            IConfiguration configuration)
        {
            _adminService = adminService;
            _authService = authService;
            _logger = logger;
            _emailService = emailService;
            _configuration = configuration;
        }

        // ==================== HELPER METHODS ====================

        private async Task<bool> HasPermission(string moduleName, string permissionType)
        {
            var roleIdClaim = User.FindFirstValue("RoleId");
            if (string.IsNullOrEmpty(roleIdClaim)) return false;

            int roleId = int.Parse(roleIdClaim);
            return await _adminService.HasModulePermission(roleId, moduleName, permissionType);
        }

        private int GetCurrentUserId()
        {
            var userIdClaim = User.FindFirstValue("UserId");
            return string.IsNullOrEmpty(userIdClaim) ? 0 : int.Parse(userIdClaim);
        }

        // ==================== AUTH ENDPOINTS (PUBLIC) ====================

        [HttpPost("auth/Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { success = false, message = "Invalid model state", errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage) });
                }

                var email = model.Email.Trim().ToLower();

                // Validate user credentials
                var userId = _authService.ValidateLogin(email, model.Password);

                if (userId <= 0)
                {
                    return Unauthorized(new { success = false, message = "Invalid email or password!" });
                }

                // Get user data
                var user = await _authService.GetByEmailAsync(email);

                if (user == null)
                {
                    return NotFound(new { success = false, message = "User not found!" });
                }

                // Generate OTP
                string otp = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
                DateTime expiry = DateTime.UtcNow.AddMinutes(10);

                await _authService.SaveOtpAsync(email, otp, expiry);

                // Send Email - Mobile CMS Branding
                await _emailService.SendEmail(
                    email,
                    "Your authentication code for Mobile CMS",
                    $@"
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .container {{ max-width: 500px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #0d1527, #0099cc); padding: 20px; text-align: center; color: white; }}
                    .content {{ padding: 20px; background: #f9f9f9; }}
                    .otp-code {{ font-size: 28px; font-weight: bold; color: #0099cc; text-align: center; padding: 15px; }}
                    .footer {{ text-align: center; font-size: 12px; color: #666; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='header'>
                        <h2>Mobile CMS</h2>
                    </div>
                    <div class='content'>
                        <p>Hello {user.FullName ?? user.UserName ?? "User"},</p>
                        <p>Your authentication code is:</p>
                        <div class='otp-code'><strong>{otp}</strong></div>
                        <p>This code is valid for <strong>10 minutes</strong>.</p>
                        <p>If you didn't request this, please ignore this email.</p>
                    </div>
                    <div class='footer'>
                        <p>&copy; {DateTime.Now.Year} Mobile CMS. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>"
                );

                // Store email in session
                HttpContext.Session.SetString("MFA_Email", email);
                HttpContext.Session.SetString("MFA_UserId", userId.ToString());
                HttpContext.Session.SetString("MFA_RememberMe", model.RememberMe.ToString());

                return Ok(new { success = true, message = "OTP sent to your email", requiresOtp = true, email = email });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login error");
                return StatusCode(500, new { success = false, message = "Something went wrong!" });
            }
        }


        [HttpPost("auth/verify-mfa")]
        public async Task<IActionResult> VerifyMfa([FromBody] VerifyOtpDto dto)
        {
            try
            {
                if (dto == null || string.IsNullOrWhiteSpace(dto.Otp))
                {
                    return BadRequest(new { success = false, message = "OTP is required" });
                }

                var email = HttpContext.Session.GetString("MFA_Email");
                var userId = HttpContext.Session.GetString("MFA_UserId");
                var rememberMe = HttpContext.Session.GetString("MFA_RememberMe") == "True";

                if (string.IsNullOrEmpty(email))
                {
                    return BadRequest(new { success = false, message = "Session expired. Please login again." });
                }

                var otpRow = await _authService.ValidateOtpAsync(email, dto.Otp);

                if (otpRow == null)
                {
                    return BadRequest(new { success = false, message = "Invalid or expired OTP" });
                }

                var user = await _authService.GetByEmailAsync(email);

                if (user == null)
                {
                    return NotFound(new { success = false, message = "User not found" });
                }

                // ========== LOAD PERMISSIONS DYNAMICALLY FROM DATABASE ==========
                var permissions = await _adminService.GetRolePermissions(user.RoleId);

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserId),
                    new Claim(ClaimTypes.Email, user.Email ?? ""),
                    new Claim(ClaimTypes.Name, user.FullName ?? ""),
                    new Claim(ClaimTypes.Role, user.RoleName ?? "User"),
                    new Claim("UserId", user.UserId),
                    new Claim("DepartmentId", user.DepartmentId.ToString()),
                    new Claim("EmployeeId", user.EmployeeId ?? ""),
                    new Claim("MobileNo", user.MobileNo ?? ""),
                    new Claim("RoleId", user.RoleId.ToString()),
                    new Claim("RoleName", user.RoleName ?? "User")
                };

                // ========== ADD PERMISSION CLAIMS DYNAMICALLY ==========
                foreach (var perm in permissions)
                {
                    claims.Add(new Claim($"Perm_{perm.ModuleName}_View", perm.CanView.ToString()));
                    claims.Add(new Claim($"Perm_{perm.ModuleName}_Create", perm.CanCreate.ToString()));
                    claims.Add(new Claim($"Perm_{perm.ModuleName}_Modify", perm.CanModify.ToString()));
                    claims.Add(new Claim($"Perm_{perm.ModuleName}_Delete", perm.CanDelete.ToString()));
                }

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = rememberMe,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8)
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(identity),
                    authProperties
                );

                HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString());
                await _authService.MarkOtpUsedAsync(otpRow.Id);
                HttpContext.Session.Remove("MFA_Email");
                HttpContext.Session.Remove("MFA_UserId");
                HttpContext.Session.Remove("MFA_RememberMe");

                return Ok(new { success = true, message = "Login successful", user = new { user.UserId, user.Email, user.FullName, user.RoleName } });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MFA verification failed");
                return StatusCode(500, new { success = false, message = "Something went wrong" });
            }
        }

        [HttpPost("auth/resend-otp")]
        public async Task<IActionResult> ResendOtp()
        {
            var email = HttpContext.Session.GetString("MFA_Email");

            if (string.IsNullOrEmpty(email))
                return BadRequest(new { success = false, message = "Session expired" });

            string otp = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
            DateTime expiry = DateTime.UtcNow.AddMinutes(10);

            await _authService.SaveOtpAsync(email, otp, expiry);

            await _emailService.SendEmail(
                email,
                "Login OTP - EAM System",
                $"Your OTP is {otp}. Valid for 10 minutes."
            );

            return Ok(new { success = true, message = "OTP resent successfully" });
        }

        [HttpPost("auth/send-otp-email")]
        public async Task<IActionResult> SendOtpForEmailVerification([FromBody] EmailDto dto)
        {
            try
            {
                if (dto == null || string.IsNullOrWhiteSpace(dto.Email))
                    return BadRequest(new { success = false, message = "Email is required" });

                var email = dto.Email.Trim().ToLower();

                // Check if user exists
                var user = await _authService.GetByEmailAsync(email);

                if (user == null)
                    return NotFound(new { success = false, message = "Email not registered" });

                // Generate OTP
                string otp = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
                DateTime expiry = DateTime.UtcNow.AddMinutes(10);

                // Save OTP
                await _authService.SaveOtpAsync(email, otp, expiry);

                // Send Email
                await _emailService.SendEmail(
                    email,
                    "Email Verification - Mobile CMS",
                    $"Your OTP is {otp}. Valid for 10 minutes."
                );

                // Store email in session
                HttpContext.Session.SetString("MFA_Email", email);

                return Ok(new { success = true, message = "OTP sent successfully", redirectUrl = "/Dashboard" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending OTP for email verification");
                return StatusCode(500, new { success = false, message = "Something went wrong" });
            }
        }

        [HttpPost("auth/forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
        {
            try
            {
                if (dto == null || string.IsNullOrWhiteSpace(dto.Email))
                    return BadRequest(new { success = false, message = "Email is required" });

                var email = dto.Email.Trim().ToLower();

                var user = await _authService.GetByEmailAsync(email);

                if (user == null)
                    return NotFound(new { success = false, message = "Email not found" });

                string otp = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
                DateTime expiry = DateTime.UtcNow.AddMinutes(10);

                await _authService.SaveOtpAsync(email, otp, expiry);

                await _emailService.SendEmail(
                    email,
                    "EAM Password Reset OTP",
                    $"Your OTP for password reset is {otp}. Valid for 10 minutes."
                );

                return Ok(new { success = true, message = "OTP sent to email" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Forgot password error");
                return StatusCode(500, new { success = false, message = "Something went wrong" });
            }
        }

        [HttpPost("auth/reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.NewPassword))
                return BadRequest(new { success = false, message = "Invalid data" });

            var email = dto.Email.Trim().ToLower();

            var otpRow = await _authService.ValidateOtpAsync(email, dto.Otp);

            if (otpRow == null)
                return BadRequest(new { success = false, message = "Invalid or expired OTP" });

            await _authService.ResetPasswordAsync(email, dto.NewPassword);
            await _authService.MarkOtpUsedAsync(otpRow.Id);

            return Ok(new { success = true, message = "Password reset successful" });
        }

        [HttpGet("auth/Logout")]
        public async Task<IActionResult> Logout()
        {
            HttpContext.Session.Clear();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogInformation("User logged out.");
            return Ok(new { success = true, message = "Logged out successfully", redirectUrl = "/" });
        }

        [HttpGet("auth/Dashboard")]
        [Authorize]
        public IActionResult Dashboard()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userName = User.FindFirstValue(ClaimTypes.Name);
            var userEmail = User.FindFirstValue(ClaimTypes.Email);
            var userRole = User.FindFirstValue(ClaimTypes.Role);

            return Ok(new
            {
                success = true,
                data = new
                {
                    UserId = userId,
                    UserName = userName,
                    UserEmail = userEmail,
                    UserRole = userRole
                }
            });
        }

        [HttpGet("auth/GetCurrentUserRole")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUserRole()
        {
            try
            {
                var userIdClaim = User.FindFirst("UserId")?.Value;
                if (string.IsNullOrEmpty(userIdClaim))
                    return Ok(new { success = true, roleId = 0 });

                var userId = int.Parse(userIdClaim);

                using var connection = new NpgsqlConnection(_configuration.GetConnectionString("DefaultConnection"));
                var sql = "SELECT role_id FROM public.tbl_users WHERE user_id = @UserId";
                var roleId = await connection.ExecuteScalarAsync<int>(sql, new { UserId = userId });

                return Ok(new { success = true, roleId = roleId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user role");
                return Ok(new { success = false, roleId = 0 });
            }
        }

        // ==================== USER MANAGEMENT APIS ====================

        [HttpGet("admin/UserList")]
        [Authorize]
        public async Task<IActionResult> UserList()
        {
            if (!await HasPermission("User Management", "View"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to view users" });
            }

            var users = await _adminService.GetAllUsersAsync();
            return Ok(new { success = true, data = users });
        }

        [HttpGet("admin/users/{id}")]
        [Authorize]
        public async Task<IActionResult> GetUserById(int id)
        {
            if (!await HasPermission("User Management", "View"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to view users" });
            }

            var users = await _adminService.GetAllUsersAsync();
            var user = users.FirstOrDefault(u => u.UserId == id);

            if (user == null)
                return NotFound(new { success = false, message = "User not found" });

            return Ok(new { success = true, data = user });
        }

        [HttpPost("admin/UserCreation")]
        [Authorize]
        public async Task<IActionResult> CreateUser([FromBody] RegisterModel model)
        {
            if (!await HasPermission("User Management", "Create"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to create users" });
            }

            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { success = false, message = "Invalid model state", errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage) });
                }

                if (model.RoleId <= 0)
                {
                    return BadRequest(new { success = false, message = "Please select a role!" });
                }

                if (model.DepartmentId <= 0)
                {
                    return BadRequest(new { success = false, message = "Please select a department!" });
                }

                var createdBy = User.Identity?.Name ?? "Admin";
                var userId = await _adminService.RegisterUser(model, createdBy);

                if (userId > 0)
                {
                    return Ok(new { success = true, message = $"User '{model.FullName}' registered successfully!", userId = userId });
                }
                else
                {
                    return BadRequest(new { success = false, message = "Registration failed! Please try again." });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user");
                return StatusCode(500, new { success = false, message = $"Error: {ex.Message}" });
            }
        }

        // ==================== DEPARTMENT MANAGEMENT APIS ====================

        [HttpGet("admin/AddDepartment")]
        [Authorize]
        public async Task<IActionResult> GetDepartments()
        {
            if (!await HasPermission("User Management", "View"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to view departments" });
            }

            var departments = await _adminService.GetActiveDepartments();
            return Ok(new { success = true, data = departments });
        }

        [HttpPost("admin/AddDepartment")]
        [Authorize]
        public async Task<IActionResult> CreateDepartment([FromBody] CreateDepartment department)
        {
            if (!await HasPermission("User Management", "Create"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to add departments" });
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(new { success = false, message = "Invalid data", errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage) });
            }

            var result = await _adminService.AddDepartment(department);
            if (result)
            {
                return Ok(new { success = true, message = "Department added successfully!" });
            }
            else
            {
                return BadRequest(new { success = false, message = "Failed to add department." });
            }
        }

        // ==================== ROLE MANAGEMENT APIS ====================

        [HttpGet("admin/Roles")]
        [Authorize]
        public async Task<IActionResult> GetRoles()
        {
            if (!await HasPermission("User Management", "View"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to view roles" });
            }

            var roles = await _adminService.GetActiveRoles();
            var userCounts = await _adminService.GetUserCountByRole();

            return Ok(new { success = true, data = roles, userCounts = userCounts });
        }

        [HttpGet("admin/roles/{id}")]
        [Authorize]
        public async Task<IActionResult> GetRoleById(int id)
        {
            if (!await HasPermission("User Management", "View"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to view roles" });
            }

            var roles = await _adminService.GetActiveRoles();
            var role = roles.FirstOrDefault(r => r.roleid == id);

            if (role == null)
                return NotFound(new { success = false, message = "Role not found" });

            return Ok(new { success = true, data = role });
        }

        [HttpPost("admin/Roles")]
        [Authorize]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
        {
            if (!await HasPermission("User Management", "Create"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to create roles" });
            }

            try
            {
                if (string.IsNullOrEmpty(request.RoleName))
                    return BadRequest(new { success = false, message = "Role name is required" });

                var role = new RoleModel { rolename = request.RoleName };
                var result = await _adminService.CreateRole(role);
                return Ok(new { success = true, message = $"Role '{request.RoleName}' created", roleId = result.roleid });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating role");
                return StatusCode(500, new { success = false, message = "Error creating role", error = ex.Message });
            }
        }

        [HttpDelete("admin/Roles/{id}")]
        [Authorize]
        public async Task<IActionResult> DeleteRole(int id)
        {
            if (!await HasPermission("User Management", "Delete"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to delete roles" });
            }

            try
            {
                var hasUsers = await _adminService.HasUsersInRole(id);
                if (hasUsers)
                    return BadRequest(new { success = false, message = "Cannot delete role with assigned users" });

                var result = await _adminService.DeleteRole(id);
                if (result)
                    return Ok(new { success = true, message = "Role deleted successfully" });

                return NotFound(new { success = false, message = "Role not found" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting role {RoleId}", id);
                return StatusCode(500, new { success = false, message = "Error deleting role", error = ex.Message });
            }
        }

        [HttpGet("admin/Roles/{roleId}/Permissions")]
        [Authorize]
        public async Task<IActionResult> GetRolePermissions(int roleId)
        {
            if (!await HasPermission("User Management", "View"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to view role permissions" });
            }

            try
            {
                var permissions = await _adminService.GetRolePermissions(roleId);
                return Ok(new { success = true, data = permissions });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting permissions for role {RoleId}", roleId);
                return StatusCode(500, new { success = false, message = "Error retrieving permissions", error = ex.Message });
            }
        }

        [HttpPut("admin/Roles/{roleId}/Permissions")]
        [Authorize]
        public async Task<IActionResult> UpdateRolePermissions(int roleId, [FromBody] List<RolePermission> permissions)
        {
            if (!await HasPermission("User Management", "Modify"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to update role permissions" });
            }

            try
            {
                if (permissions == null || !permissions.Any())
                    return BadRequest(new { success = false, message = "Permissions data is required" });

                var result = await _adminService.UpdateRolePermissions(roleId, permissions);
                if (result)
                    return Ok(new { success = true, message = "Permissions updated successfully" });

                return BadRequest(new { success = false, message = "Failed to update permissions" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating permissions for role {RoleId}", roleId);
                return StatusCode(500, new { success = false, message = "Error updating permissions", error = ex.Message });
            }
        }

        [HttpGet("admin/api/Roles/{roleId}/HasPermission")]
        [Authorize]
        public async Task<IActionResult> HasModulePermission(int roleId, string moduleName, string permissionType)
        {
            try
            {
                var hasPermission = await _adminService.HasModulePermission(roleId, moduleName, permissionType);
                return Ok(new { success = true, hasPermission = hasPermission });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking permission");
                return Ok(new { success = false, hasPermission = false });
            }
        }

        // ==================== FORM MANAGEMENT APIS ====================

        [HttpGet("admin/FormsList")]
        [Authorize]
        public async Task<IActionResult> GetAllForms()
        {
            var userIdClaim = User.FindFirstValue("UserId");
            if (string.IsNullOrEmpty(userIdClaim))
            {
                return Unauthorized(new { success = false, message = "User not authenticated" });
            }

            bool canViewAllForms = await HasPermission("Manage Forms", "View");

            if (!canViewAllForms)
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to view all forms." });
            }

            var forms = _adminService.GetForms();
            return Ok(new { success = true, data = forms });
        }

        [HttpGet("User/FormsList")]
        [Authorize]
        public async Task<IActionResult> GetUserForms()
        {
            var userIdClaim = User.FindFirstValue("UserId");
            var roleIdClaim = User.FindFirstValue("RoleId");

            if (string.IsNullOrEmpty(userIdClaim))
            {
                return Unauthorized(new { success = false, message = "User not authenticated" });
            }

            // Check if user has "View All Forms" permission (Admin only)
            bool canViewAllForms = await HasPermission("Manage Forms", "View");

            if (canViewAllForms)
            {
                return StatusCode(403, new
                {
                    success = false,
                    message = "Admins should use /api/admin/FormsList endpoint. This endpoint is for regular users only."
                });
            }

            int userId = int.Parse(userIdClaim);
            var forms = _adminService.GetFormsForUser(userId);

            return Ok(new { success = true, data = forms });
        }

        [HttpGet("admin/FormBuilder")]
        [Authorize]
        public async Task<IActionResult> FormBuilder()
        {
            if (!await HasPermission("Manage Forms", "Create"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to create forms" });
            }

            var model = new CreateFormRequest
            {
                FormTitle = "New Form",
                FormDescription = "",
                CreatedBy = User.Identity?.Name ?? "Admin",
                Fields = new List<FormField>(),
                UserId = 0
            };

            var users = _adminService.GetActiveUsers();
            return Ok(new { success = true, data = model, users = users });
        }

        [HttpPost("admin/FormBuilder/Create")]
        [Authorize]
        public async Task<IActionResult> CreateForm([FromBody] CreateFormRequest request)
        {
            if (!await HasPermission("Manage Forms", "Create"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to create forms" });
            }

            try
            {
                request.CreatedBy = User.Identity?.Name ?? "Admin";
                request.Fields ??= new List<FormField>();

                if (request.UserId <= 0)
                {
                    return BadRequest(new { success = false, message = "Please select a user to assign this form" });
                }

                if (string.IsNullOrWhiteSpace(request.FormTitle))
                {
                    return BadRequest(new { success = false, message = "Form title is required" });
                }

                foreach (var field in request.Fields)
                {
                    if (string.IsNullOrWhiteSpace(field.FieldName))
                    {
                        return BadRequest(new { success = false, message = "All fields must have labels" });
                    }
                }

                var formId = await _adminService.CreateFormAsync(
                    request.FormTitle?.Trim() ?? "Untitled Form",
                    request.FormDescription?.Trim() ?? "",
                    request.CreatedBy,
                    request.Fields,
                    true,
                    request.UserId
                );

                return Ok(new { success = true, message = $"Form '{request.FormTitle}' saved successfully!", formId = formId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating form");
                return StatusCode(500, new { success = false, message = $"Error creating form: {ex.Message}" });
            }
        }

        [HttpGet("admin/SubmitForm/{id}")]
        [Authorize]
        public async Task<IActionResult> SubmitForm(int id)
        {
            try
            {
                var userIdClaim = User.FindFirstValue("UserId");
                if (string.IsNullOrEmpty(userIdClaim))
                {
                    return Unauthorized(new { success = false, message = "User not authenticated" });
                }

                int userId = int.Parse(userIdClaim);

                var forms = _adminService.GetForms();
                var form = forms.FirstOrDefault(f => f.FormId == id);

                if (form == null)
                {
                    return NotFound(new { success = false, message = $"Form with ID {id} not found" });
                }

                if (!form.IsActive)
                {
                    return BadRequest(new { success = false, message = "This form is currently inactive" });
                }

                bool hasViewPermission = await HasPermission("Manage Forms", "View");

                if (!hasViewPermission && form.UserId != userId)
                {
                    return StatusCode(403, new { success = false, message = "You don't have permission to submit this form" });
                }

                var formFields = _adminService.GetFormFields(id);

                var viewModel = new
                {
                    FormId = form.FormId,
                    FormTitle = form.FormTitle,
                    FormDescription = form.FormDescription,
                    TableName = form.TableName,
                    Fields = formFields.Select(f => new
                    {
                        Name = f.FieldName,
                        Label = f.FieldName.Replace("_", " "),
                        Type = f.FieldType.ToLower(),
                        Required = f.IsRequired,
                        Options = !string.IsNullOrEmpty(f.Options)
                            ? f.Options.Split(',').Select(o => o.Trim()).ToList()
                            : new List<string>(),
                        Placeholder = f.Placeholder,
                        Order = f.FieldOrder
                    }).OrderBy(f => f.Order).ToList()
                };

                return Ok(new { success = true, data = viewModel });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading form");
                return StatusCode(500, new { success = false, message = $"Error loading form: {ex.Message}" });
            }
        }

        [HttpPost("admin/SubmitFormData/{id}")]
        [Authorize]
        public async Task<IActionResult> SubmitFormData(int id, [FromBody] Dictionary<string, object> formData)
        {
            try
            {
                var userIdClaim = User.FindFirstValue("UserId");
                if (string.IsNullOrEmpty(userIdClaim))
                {
                    return Unauthorized(new { success = false, message = "User not authenticated" });
                }

                int userId = int.Parse(userIdClaim);

                var forms = _adminService.GetForms();
                var form = forms.FirstOrDefault(f => f.FormId == id);

                if (form == null)
                {
                    return NotFound(new { success = false, message = $"Form with ID {id} not found" });
                }

                bool hasViewPermission = await HasPermission("Manage Forms", "View");

                if (!hasViewPermission && form.UserId != userId)
                {
                    return StatusCode(403, new { success = false, message = "You don't have permission to submit this form" });
                }

                if (formData == null || formData.Count == 0)
                {
                    return BadRequest(new { success = false, message = "No form data received" });
                }

                // Convert to Dictionary<string, string>
                var stringData = new Dictionary<string, string>();
                foreach (var item in formData)
                {
                    stringData[item.Key] = item.Value?.ToString() ?? "";
                }

                _adminService.SaveFormData(id, stringData, userId);

                return Ok(new { success = true, message = "Form submitted successfully!" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error submitting form: {FormId}", id);
                return StatusCode(500, new { success = false, message = $"Error submitting form: {ex.Message}" });
            }
        }
        [HttpPost("admin/DeleteForm/{id}")]
        [Authorize]
        public async Task<IActionResult> DeleteForm(int id)
        {
            if (!await HasPermission("Manage Forms", "Delete"))
            {
                return StatusCode(403, new { success = false, message = "You don't have permission to delete forms" });
            }

            try
            {
                var forms = _adminService.GetForms();
                var form = forms.FirstOrDefault(f => f.FormId == id);

                if (form == null)
                {
                    return NotFound(new { success = false, message = $"Form with ID {id} not found" });
                }

                bool deleted = _adminService.DeleteForm(id);

                if (deleted)
                {
                    return Ok(new { success = true, message = $"Form '{form.FormTitle}' deleted successfully!" });
                }
                else
                {
                    return BadRequest(new { success = false, message = $"Failed to delete form '{form.FormTitle}'" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting form: {FormId}", id);
                return StatusCode(500, new { success = false, message = $"Error deleting form: {ex.Message}" });
            }
        }

        [HttpGet("admin/forms/{id}/fields")]
        [Authorize]
        public IActionResult GetFormFields(int id)
        {
            var formFields = _adminService.GetFormFields(id);
            return Ok(new { success = true, data = formFields });
        }

        // ==================== HEALTH CHECK ====================

      
    }
}