namespace CMS.Models
{
    // For login
    public class LoginModel
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool RememberMe { get; set; }
    }





    public class UserModel
    {
        public string UserId { get; set; } = string.Empty;

        public string EmployeeId { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string MobileNo { get; set; } = string.Empty;
        public int RoleId { get; set; }
        public string RoleName { get; set; } = string.Empty;
        public int DepartmentId { get; set; }
        public string Site { get; set; } = string.Empty;
        public string Shift { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
    }


    public class UserOtps
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Otp { get; set; }
        public DateTime Expiry { get; set; }
        public bool Used { get; set; }
    }

    public class ResetPasswordDto
    {
        public string Email { get; set; } = null!;
        public string Otp { get; set; } = null!;
        public string NewPassword { get; set; } = null!;
    }

    public class ChangePasswordDto
    {
        public string OldPassword { get; set; } = null!;
        public string NewPassword { get; set; } = null!;
    }

    public class ForgotPasswordDto
    {
        public string Email { get; set; } = null!;
    }

    public class VerifyOtpDto
    {
        public string Otp { get; set; } = string.Empty;
    }

    public class EmailDto
    {
        public string Email { get; set; }
    }
}
