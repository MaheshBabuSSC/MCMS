using CMS.Data;
using CMS.Models;
using CMS.Security;
using Dapper;
using Microsoft.EntityFrameworkCore;


namespace CMS.Services
{
    public class AuthService
    {
        private readonly AppDbContext _context;
        private readonly ILogger<AuthService> _logger;

        public AuthService(AppDbContext context, ILogger<AuthService> logger)
        {
            _context = context;
            _logger = logger;
        }

        // ==================== ORIGINAL LOGIN METHODS ====================

        public int ValidateLogin(string email, string password)
        {
            try
            {
                email = email?.Trim().ToLower();
                password = password?.Trim();

                var user = _context.Database
                    .SqlQueryRaw<LoginResult>(
                        "SELECT UserId, PasswordHash, PasswordSalt FROM tbl_users WHERE LOWER(Email) = LOWER({0}) AND IsActive = true",
                        email
                    )
                    .AsEnumerable()
                    .FirstOrDefault();

                if (user == null)
                {
                    _logger.LogWarning($"User not found: {email}");
                    return 0;
                }

                bool isValid = false;

                // Detect BCrypt hash
                if (!string.IsNullOrEmpty(user.PasswordHash) && user.PasswordHash.StartsWith("$2"))
                {
                    isValid = BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
                }
                else
                {
                    if (string.IsNullOrEmpty(user.PasswordHash) || string.IsNullOrEmpty(user.PasswordSalt))
                        return 0;

                    byte[] hash = Convert.FromBase64String(user.PasswordHash);
                    byte[] salt = Convert.FromBase64String(user.PasswordSalt);
                    isValid = PasswordHelper.VerifyPassword(password, hash, salt);
                }

                return isValid ? user.UserId : 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating login for {Email}", email);
                return 0;
            }
        }

        public UserModel GetUserByEmail(string email)
        {
            try
            {
                var sql = @"
                    SELECT 
                        u.UserId,
                        u.EmployeeId,
                        u.FullName,
                        u.UserName,
                        u.Email,
                        u.MobileNo,
                        u.RoleId,
                        r.RoleName,
                        u.DepartmentId,
                        u.Site,
                        u.Shift,
                        u.Location
                    FROM tbl_users u
                    LEFT JOIN tbl_roles r ON u.RoleId = r.RoleId
                    WHERE LOWER(u.Email) = LOWER({0}) AND u.IsActive = true";

                var user = _context.Database
                    .SqlQueryRaw<UserModel>(sql, email)
                    .AsEnumerable()
                    .FirstOrDefault();

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user by email: {Email}", email);
                return null;
            }
        }

        // ==================== OTP-BASED LOGIN METHODS ====================

        public async Task<UserModel?> GetByEmailAsync(string email)
        {
            using var conn = _context.CreateConnection();
            conn.Open();

            var user = await conn.QueryFirstOrDefaultAsync<UserModel>(
                @"SELECT 
                    userid AS UserId,
                    employeeid AS EmployeeId,
                    fullname AS FullName,
                    username AS UserName,
                    email AS Email,
                    mobileno AS MobileNo,
                    roleid AS RoleId,
                    (SELECT rolename FROM tbl_roles WHERE roleid = u.roleid) AS RoleName,
                    departmentid AS DepartmentId,
                    site AS Site,
                    shift AS Shift,
                    location AS Location
                FROM tbl_users u
                WHERE LOWER(email) = LOWER(@Email) AND IsActive = true
                LIMIT 1",
                new { Email = email }
            );

            return user;
        }

        public async Task SaveOtpAsync(string email, string otp, DateTime expiry)
        {
            using var conn = _context.CreateConnection();
            conn.Open();

            await conn.ExecuteAsync(
                @"INSERT INTO users_otp (email, otp, expiry, is_used)
                VALUES (@Email, @Otp, @Expiry, false)",
                new { Email = email, Otp = otp, Expiry = expiry }
            );
        }

        public async Task<UserOtps?> ValidateOtpAsync(string email, string otp)
        {
            using var conn = _context.CreateConnection();
            conn.Open();

            return await conn.QueryFirstOrDefaultAsync<UserOtps>(
                @"SELECT * FROM users_otp
                WHERE email = @Email
                AND otp = @Otp
                AND is_used = false
                AND expiry > NOW()
                ORDER BY id DESC
                LIMIT 1",
                new { Email = email, Otp = otp }
            );
        }

        public async Task ResetPasswordAsync(string email, string newPassword)
        {
            using var conn = _context.CreateConnection();

            var hash = BCrypt.Net.BCrypt.HashPassword(newPassword);

            await conn.ExecuteAsync(
                @"UPDATE tbl_users
                SET passwordhash = @PasswordHash
                WHERE LOWER(email) = LOWER(@Email)",
                new { Email = email, PasswordHash = hash }
            );
        }

        public async Task MarkOtpUsedAsync(int id)
        {
            using var conn = _context.CreateConnection();
            conn.Open();

            await conn.ExecuteAsync(
                @"UPDATE users_otp
                SET is_used = true
                WHERE id = @Id",
                new { Id = id }
            );
        }

        private class LoginResult
        {
            public int UserId { get; set; }
            public string PasswordHash { get; set; } = string.Empty;
            public string PasswordSalt { get; set; } = string.Empty;
        }
    }
}
