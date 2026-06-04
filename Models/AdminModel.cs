namespace CMS.Models
{
    // For User Registration
    public class RegisterModel
    {
        public int UserId { get; set; }
        public string EmployeeId { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string MobileNo { get; set; } = string.Empty;
        public int DepartmentId { get; set; }
        public int RoleId { get; set; }
        public string Site { get; set; } = string.Empty;
        public string Shift { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public bool IsActive { get; set; } = true;
        public List<RoleModel> Roles { get; set; } = new();
        public List<DepartmentModel> Departments { get; set; } = new();
    }

    // For User List
    public class UsersList
    {
        public int UserId { get; set; }
        public string EmployeeId { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string MobileNo { get; set; } = string.Empty;
        public int DepartmentId { get; set; }
        public string DepartmentName { get; set; } = string.Empty;
        public int RoleId { get; set; }
        public string RoleName { get; set; } = string.Empty;
        public string Site { get; set; } = string.Empty;
        public string Shift { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public DateTime CreatedDate { get; set; }
    }

    // For Roles
    public class RoleModel
    {
        public int roleid { get; set; }
        public string rolename { get; set; } = string.Empty;
        public DateTime? createdon { get; set; }
        public bool isactive { get; set; } = true;
    }

    // For Departments
    public class DepartmentModel
    {
        public int department_id { get; set; }
        public string department_name { get; set; } = string.Empty;
    }

    // For Adding Department
    public class CreateDepartment
    {
        public string DepartmentName { get; set; } = string.Empty;
        public string DepartmentContactPerson { get; set; } = string.Empty;
        public string Designation { get; set; } = string.Empty;
        public string MobileNo { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }

    // ==================== FORM BUILDER MODELS ====================

    public class FormField
    {
        public string FieldName { get; set; } = string.Empty;
        public string FieldType { get; set; } = string.Empty;
        public string Options { get; set; } = string.Empty;
        public int FieldOrder { get; set; }
        public bool IsRequired { get; set; } = false;
        public string Placeholder { get; set; } = string.Empty;
    }

    public class CreateFormRequest
    {
        public int? FormId { get; set; }
        public string FormTitle { get; set; } = string.Empty;
        public string FormDescription { get; set; } = string.Empty;
        public string CreatedBy { get; set; } = string.Empty;
        public int UserId { get; set; }  // Changed from DepartmentId
        public List<FormField> Fields { get; set; } = new List<FormField>();
    }

    public class FormSummary
    {
        public int FormId { get; set; }
        public string FormTitle { get; set; } = string.Empty;
        public string FormDescription { get; set; } = string.Empty;
        public string CreatedBy { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public bool IsActive { get; set; }
        public string TableName { get; set; } = string.Empty;
        public int UserId { get; set; }
        public string DepartmentName { get; set; } = string.Empty;

        public List<FormField> FormFields { get; set; } = new List<FormField>();

    }

    public class DynamicFormViewModel
    {
        public int FormId { get; set; }
        public string FormTitle { get; set; } = string.Empty;
        public string FormDescription { get; set; } = string.Empty;
        public string TableName { get; set; } = string.Empty;
        public List<DynamicFormFieldViewModel> Fields { get; set; } = new();
    }

    public class DynamicFormFieldViewModel
    {
        public string Name { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public bool Required { get; set; }
        public List<string> Options { get; set; } = new();
        public string Placeholder { get; set; } = string.Empty;
        public int Order { get; set; }
    }

    // For Form Builder Department
    public class Department
    {
        public int department_id { get; set; }
        public string department_name { get; set; } = string.Empty;
        public bool isactive { get; set; }
    }
    public class RolePermission
    {
        public string ModuleName { get; set; } = string.Empty;
        public bool CanView { get; set; }
        public bool CanCreate { get; set; }
        public bool CanModify { get; set; }
        public bool CanDelete { get; set; }
    }
    public class CreateRoleRequest
    {
        public string RoleName { get; set; } = string.Empty;
    }


    public class UserDto
    {
        public int UserId { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Username { get; set; }
        public int RoleId { get; set; }
        public int DepartmentId { get; set; }
        public string EmployeeId { get; set; }
        public string RoleName { get; set; } 
    }

    //public class FormSubmissionDto
    //{
    //    public int Id { get; set; }
    //    public int? SubmittedByUserId { get; set; }
    //    public string SubmittedByName { get; set; }
    //    public DateTime? SubmittedAt { get; set; }
    //    public string Text { get; set; }
    //    public string Number { get; set; }
    //    public string Date { get; set; }

    //    // For UI display - convert to dictionary
    //    public Dictionary<string, object> FormData
    //    {
    //        get
    //        {
    //            var dict = new Dictionary<string, object>();
    //            if (!string.IsNullOrEmpty(Text)) dict["Text"] = Text;
    //            if (!string.IsNullOrEmpty(Number)) dict["Number"] = Number;
    //            if (!string.IsNullOrEmpty(Date)) dict["Date"] = Date;
    //            return dict;
    //        }
    //    }
    //}



}
