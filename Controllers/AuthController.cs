using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Npgsql;
using Dapper;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;
using System.Security.Cryptography;
using CMS.Services;
using CMS.Models;

namespace CMS.Controllers
{
    [Route("")]
    public class AuthController : Controller
    {
        private readonly AuthService _authService;
        private readonly ILogger<AuthController> _logger;
        private readonly EmailService _emailService;
        private readonly IConfiguration _configuration;
        private readonly IAdminService _adminService;

        public AuthController(AuthService authService, ILogger<AuthController> logger,
            EmailService emailService, IConfiguration configuration, IAdminService adminService)
        {
            _authService = authService;
            _logger = logger;
            _emailService = emailService;
            _configuration = configuration;
            _adminService = adminService;  // ← ADD THIS
        }

        // GET: / - Show login page
        [HttpGet("")]
        [HttpGet("Index")]
        public IActionResult Index()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("FormBuilder", "Admin");
            }
            return View("~/Views/CMS/Login.cshtml");
        }

        // GET: /Login - Redirect to home
        [HttpGet("Login")]
        public IActionResult Login()
        {
            return Redirect("/");
        }

        // ==================== ORIGINAL LOGIN (WITHOUT OTP) ====================
        [HttpPost("LoginOriginal")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginOriginal(LoginModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View("~/Views/CMS/Login.cshtml", model);
                }

                var userId = _authService.ValidateLogin(model.Email, model.Password);

                if (userId > 0)
                {
                    var user = _authService.GetUserByEmail(model.Email);
                    if (user == null)
                    {
                        ViewBag.Error = "User details not found!";
                        return View("~/Views/CMS/Login.cshtml", model);
                    }

                    // ========== LOAD PERMISSIONS DYNAMICALLY ==========
                    var permissions = await _adminService.GetRolePermissions(user.RoleId);

                    var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(ClaimTypes.Role, user.RoleName ?? "User"),
                new Claim("UserId", user.UserId.ToString()),
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

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = model.RememberMe,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8)
                    };

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
                    _logger.LogInformation($"User {user.Email} logged in successfully (Original flow).");
                    return RedirectToAction("FormsList", "Admin");
                }
                else
                {
                    ViewBag.Error = "Invalid email or password!";
                    return View("~/Views/CMS/Login.cshtml", model);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login error for email: {Email}", model.Email);
                ViewBag.Error = $"Login error: {ex.Message}";
                return View("~/Views/CMS/Login.cshtml", model);
            }
        }

        // ==================== OTP-BASED LOGIN FLOW ====================
        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View("~/Views/CMS/Login.cshtml", model);
                }

                var email = model.Email.Trim().ToLower();

                // Validate user credentials
                var userId = _authService.ValidateLogin(email, model.Password);

                if (userId <= 0)
                {
                    ViewBag.Error = "Invalid email or password!";
                    return View("~/Views/CMS/Login.cshtml", model);
                }

                // Get user data
                var user = await _authService.GetByEmailAsync(email);

                if (user == null)
                {
                    ViewBag.Error = "User not found!";
                    return View("~/Views/CMS/Login.cshtml", model);
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
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <title>Authentication Code</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.5;
            color: #24292f;
            background-color: #f6f8fa;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 520px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #0d1527, #0099cc);
            padding: 24px 20px;
            text-align: center;
            border-radius: 8px 8px 0 0;
        }}
        .header h1 {{
            color: #ffffff;
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }}
        .content {{
            background-color: #ffffff;
            border: 1px solid #d0d7de;
            border-top: none;
            border-radius: 0 0 8px 8px;
            padding: 32px;
        }}
        .greeting {{
            font-size: 16px;
            margin-bottom: 20px;
            color: #24292f;
        }}
        .code-box {{
            background-color: #f6f8fa;
            border: 1px solid #d0d7de;
            border-radius: 8px;
            padding: 16px 24px;
            text-align: center;
            margin: 24px 0;
        }}
        .code {{
            font-size: 32px;
            font-weight: 600;
            letter-spacing: 4px;
            color: #0d1527;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
        }}
        .warning {{
            background-color: #fff8e7;
            border-left: 4px solid #e3b341;
            padding: 12px 16px;
            margin: 24px 0;
            font-size: 13px;
            color: #5c3b00;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid #d0d7de;
            font-size: 12px;
            color: #57606a;
            text-align: center;
        }}
        .company {{
            font-weight: 600;
            color: #0d1527;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Mobile CMS</h1>
        </div>
        <div class='content'>
            <div class='greeting'>
                <strong>Please verify your identity, {user.FullName ?? user.UserName ?? "User"}.</strong>
            </div>
            
            <p>Here is your Mobile CMS authentication code:</p>
            
            <div class='code-box'>
                <span class='code'>{otp}</span>
            </div>
            
            <p>This code is valid for <strong>10 minutes</strong> and can only be used once.</p>
            
            <div class='warning'>
                <strong>⚠️ Please don't share this code with anyone:</strong> we'll never ask for it on the phone or via email.
            </div>
            
            <p style='font-size: 13px; color: #57606a;'>
                If you didn't request this authentication code, please ignore this email. 
                Your account is safe and no action is required.
            </p>
        </div>
        <div class='footer'>
            <p>You're receiving this email because a verification code was requested for your <span class='company'>Mobile CMS</span> account.</p>
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

                // Redirect to OTP Page
                return RedirectToAction("Authentication");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login error");
                ViewBag.Error = "Something went wrong!";
                return View("~/Views/CMS/Login.cshtml", model);
            }
        }

        [HttpPost("verify-mfa")]
        public async Task<IActionResult> VerifyMfa([FromBody] VerifyOtpDto dto)
        {
            try
            {
                if (dto == null || string.IsNullOrWhiteSpace(dto.Otp))
                {
                    return Json(new { success = false, message = "OTP is required" });
                }

                var email = HttpContext.Session.GetString("MFA_Email");
                var userId = HttpContext.Session.GetString("MFA_UserId");
                var rememberMe = HttpContext.Session.GetString("MFA_RememberMe") == "True";

                if (string.IsNullOrEmpty(email))
                {
                    return Json(new { success = false, message = "Session expired. Please login again." });
                }

                var otpRow = await _authService.ValidateOtpAsync(email, dto.Otp);

                if (otpRow == null)
                {
                    return Json(new { success = false, message = "Invalid or expired OTP" });
                }

                var user = await _authService.GetByEmailAsync(email);

                if (user == null)
                {
                    return Json(new { success = false, message = "User not found" });
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

                return Json(new { success = true, redirectUrl = "/Dashboard" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MFA verification failed");
                return Json(new { success = false, message = "Something went wrong" });
            }
        }

        // ==================== COMMON METHODS ====================

        [HttpPost("resend-otp")]
        public async Task<IActionResult> ResendOtp()
        {
            var email = HttpContext.Session.GetString("MFA_Email");

            if (string.IsNullOrEmpty(email))
                return Json(new { success = false, message = "Session expired" });

            string otp = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
            DateTime expiry = DateTime.UtcNow.AddMinutes(10);

            await _authService.SaveOtpAsync(email, otp, expiry);

            await _emailService.SendEmail(
                email,
                "Login OTP - EAM System",
                $"Your OTP is <b>{otp}</b>. Valid for 10 minutes."
            );

            return Json(new { success = true });
        }

        [HttpPost("send-otp-email")]
        public async Task<IActionResult> SendOtpForEmailVerification([FromBody] EmailDto dto)
        {
            try
            {
                if (dto == null || string.IsNullOrWhiteSpace(dto.Email))
                    return BadRequest("Email is required");

                var email = dto.Email.Trim().ToLower();

                // Check if user exists
                var user = await _authService.GetByEmailAsync(email);

                if (user == null)
                    return NotFound("Email not registered");

                // Generate OTP
                string otp = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
                DateTime expiry = DateTime.UtcNow.AddMinutes(10);

                // Save OTP
                await _authService.SaveOtpAsync(email, otp, expiry);

                // Send Email - Mobile CMS Branding
                await _emailService.SendEmail(
                    email,
                    "Email Verification - Mobile CMS",
                    $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <title>Email Verification</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.5;
            color: #24292f;
            background-color: #f6f8fa;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 520px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #0d1527, #0099cc);
            padding: 24px 20px;
            text-align: center;
            border-radius: 8px 8px 0 0;
        }}
        .header h1 {{
            color: #ffffff;
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }}
        .content {{
            background-color: #ffffff;
            border: 1px solid #d0d7de;
            border-top: none;
            border-radius: 0 0 8px 8px;
            padding: 32px;
        }}
        .greeting {{
            font-size: 16px;
            margin-bottom: 20px;
        }}
        .code-box {{
            background-color: #f6f8fa;
            border: 1px solid #d0d7de;
            border-radius: 8px;
            padding: 16px 24px;
            text-align: center;
            margin: 24px 0;
        }}
        .code {{
            font-size: 32px;
            font-weight: 600;
            letter-spacing: 4px;
            color: #0d1527;
            font-family: monospace;
        }}
        .warning {{
            background-color: #fff8e7;
            border-left: 4px solid #e3b341;
            padding: 12px 16px;
            margin: 24px 0;
            font-size: 13px;
            color: #5c3b00;
        }}
        .footer {{
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid #d0d7de;
            font-size: 12px;
            color: #57606a;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Mobile CMS</h1>
        </div>

        <div class='content'>
            <div class='greeting'>
                <strong>Email Verification Required</strong>
            </div>

            <p>Please use the following OTP to verify your email address:</p>

            <div class='code-box'>
                <span class='code'>{otp}</span>
            </div>

            <p>This code is valid for <strong>10 minutes</strong>.</p>

            <div class='warning'>
                ⚠️ Do not share this OTP with anyone.
            </div>

            <p style='font-size: 13px; color: #57606a;'>
                If you didn't request this, you can safely ignore this email.
            </p>
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

                return Json(new { success = true, redirectUrl = "/Dashboard" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending OTP for email verification");
                return StatusCode(500, "Something went wrong");
            }
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
        {
            try
            {
                if (dto == null || string.IsNullOrWhiteSpace(dto.Email))
                    return BadRequest("Email is required");

                var email = dto.Email.Trim().ToLower();

                var user = await _authService.GetByEmailAsync(email);

                if (user == null)
                    return NotFound("Email not found");

                string otp = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
                DateTime expiry = DateTime.UtcNow.AddMinutes(10);

                await _authService.SaveOtpAsync(email, otp, expiry);

                await _emailService.SendEmail(
                    email,
                    "EAM Password Reset OTP",
                    $"Your OTP for password reset is <b>{otp}</b>. Valid for 10 minutes."
                );

                return Ok(new { success = true, message = "OTP sent to email" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Forgot password error");
                return StatusCode(500, "Something went wrong");
            }
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.NewPassword))
                return BadRequest("Invalid data");

            var email = dto.Email.Trim().ToLower();

            var otpRow = await _authService.ValidateOtpAsync(email, dto.Otp);

            if (otpRow == null)
                return BadRequest("Invalid or expired OTP");

            await _authService.ResetPasswordAsync(email, dto.NewPassword);
            await _authService.MarkOtpUsedAsync(otpRow.Id);

            return Ok(new { success = true, message = "Password reset successful" });
        }

        // GET: /Dashboard - Protected dashboard page
        [Authorize]
        [HttpGet("Dashboard")]
        public IActionResult Dashboard()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userName = User.FindFirstValue(ClaimTypes.Name);
            var userEmail = User.FindFirstValue(ClaimTypes.Email);
            var userRole = User.FindFirstValue(ClaimTypes.Role);

            ViewBag.UserId = userId;
            ViewBag.UserName = userName;
            ViewBag.UserEmail = userEmail;
            ViewBag.UserRole = userRole;

            return View("~/Views/CMS/Dashboard.cshtml");
        }

        // GET: /Logout - For direct URL access
        [HttpGet("Logout")]
        public async Task<IActionResult> Logout()
        {
            HttpContext.Session.Clear();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogInformation("User logged out.");
            return Redirect("/");
        }

        // POST: /Logout - For form submissions
        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogoutPost()
        {
            HttpContext.Session.Clear();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogInformation("User logged out via POST.");
            return Redirect("/");
        }

        [HttpGet("Authentication")]
        [AllowAnonymous]
        public IActionResult Authentication()
        {
            var email = HttpContext.Session.GetString("MFA_Email");

            if (string.IsNullOrEmpty(email))
            {
                return RedirectToAction("Login");
            }

            ViewBag.Email = email;
            return View("~/Views/CMS/OTP.cshtml");
        }

        //[HttpGet("ForgotPassword")]
        //[AllowAnonymous]
        //public IActionResult ForgotPassword()
        //{
        //    return View("~/Views/CMS/ForgotPassword.cshtml");
        //}

        //[HttpGet("EmailVerification")]
        //[AllowAnonymous]
        //public IActionResult EmailVerification()
        //{
        //    return View("~/Views/CMS/EmailVerification.cshtml");
        //}

        //[HttpGet("ModuleLanding")]
        //[AllowAnonymous]
        //public IActionResult ModuleLanding()
        //{
        //    return View("~/Views/CMS/ModuleLanding.cshtml");
        //}

        [HttpGet("GetCurrentUserRole")]
        public async Task<IActionResult> GetCurrentUserRole()
        {
            try
            {
                var userIdClaim = User.FindFirst("UserId")?.Value;
                if (string.IsNullOrEmpty(userIdClaim))
                    return Ok(new { roleId = 0 });

                var userId = int.Parse(userIdClaim);

                using var connection = new NpgsqlConnection(_configuration.GetConnectionString("DefaultConnection"));
                var sql = "SELECT role_id FROM public.tbl_users WHERE user_id = @UserId";
                var roleId = await connection.ExecuteScalarAsync<int>(sql, new { UserId = userId });

                return Ok(new { roleId = roleId });
            }
            catch (Exception ex)
            {
                return Ok(new { roleId = 0 });
            }
        }
    }
}
