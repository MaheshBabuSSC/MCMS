using CMS.Models;
using CMS.Security;
using Dapper;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Npgsql;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace CMS.Services
{
    public interface IAdminService
    {
        // User Management
        Task<List<RoleModel>> GetActiveRoles();
        Task<List<DepartmentModel>> GetActiveDepartments();
        Task<int> RegisterUser(RegisterModel model, string createdBy);
        Task<List<UsersList>> GetAllUsersAsync();
        Task<RegisterModel?> GetUserById(int userId);
        Task<bool> UpdateUser(int userId, RegisterModel model);
        Task<bool> DeleteUser(int userId);
        Task<bool> AddDepartment(CreateDepartment department);
        Task<Dictionary<int, int>> GetUserCountByRole();

        // Role Permissions
        Task<List<RolePermission>> GetRolePermissions(int roleId);
        Task<bool> UpdateRolePermissions(int roleId, List<RolePermission> permissions);
        Task<RoleModel> CreateRole(RoleModel role);
        Task<bool> DeleteRole(int roleId);
        Task<bool> HasUsersInRole(int roleId);
        Task<bool> HasModulePermission(int roleId, string moduleName, string permissionType);

        // Form Builder - Updated for User Assignment
        List<UserDto> GetActiveUsers();
        List<Department> GetActiveDepartmentsForForm();
        Task<int> CreateFormAsync(string title, string description, string createdBy, List<FormField> fields, bool isActive, int userId);
        List<FormSummary> GetForms(int? userId = null);
        List<FormSummary> GetFormsForUser(int userId);
        List<FormField> GetFormFields(int formId);  // ONLY ONE DECLARATION
        FormSummary? GetFormById(int formId);
        void SaveFormData(int formId, Dictionary<string, string> values, int submittedByUserId);
        bool DeleteForm(int formId);
    }

    public class AdminService : IAdminService
    {
        private readonly string _connectionString;
        private readonly ILogger<AdminService> _logger;

        public AdminService(IConfiguration configuration, ILogger<AdminService> logger)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
            _logger = logger;
        }

        private NpgsqlConnection CreateConnection()
        {
            return new NpgsqlConnection(_connectionString);
        }

        // ==================== USER MANAGEMENT ====================

        public async Task<List<RoleModel>> GetActiveRoles()
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();
            var sql = "SELECT role_id AS RoleId, role_name AS RoleName FROM public.fn_get_active_roles()";
            return (await connection.QueryAsync<RoleModel>(sql)).ToList();
        }

        public async Task<List<DepartmentModel>> GetActiveDepartments()
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();
            var sql = "SELECT * FROM public.fn_get_active_departments() ORDER BY department_name";
            return (await connection.QueryAsync<DepartmentModel>(sql)).ToList();
        }

        public async Task<int> RegisterUser(RegisterModel model, string createdBy)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            using var transaction = await connection.BeginTransactionAsync();

            try
            {
                PasswordHelper.CreatePasswordHash(model.Password, out byte[] hash, out byte[] salt);
                string hashBase64 = Convert.ToBase64String(hash);
                string saltBase64 = Convert.ToBase64String(salt);

                using var cmd = new NpgsqlCommand(
                    "CALL sp_insert_user_details(@p_employee_id, @p_full_name, @p_user_name, @p_email, @p_password_hash, @p_password_salt, @p_mobile_no, @p_department_id, @p_role_id, @p_site, @p_shift, @p_location, @p_created_by, NULL)",
                    connection
                );
                cmd.Transaction = transaction;

                cmd.Parameters.AddWithValue("@p_employee_id", model.EmployeeId);
                cmd.Parameters.AddWithValue("@p_full_name", model.FullName);
                cmd.Parameters.AddWithValue("@p_user_name", model.UserName);
                cmd.Parameters.AddWithValue("@p_email", model.Email);
                cmd.Parameters.AddWithValue("@p_password_hash", hashBase64);
                cmd.Parameters.AddWithValue("@p_password_salt", saltBase64);
                cmd.Parameters.AddWithValue("@p_mobile_no", model.MobileNo);
                cmd.Parameters.AddWithValue("@p_department_id", model.DepartmentId);
                cmd.Parameters.AddWithValue("@p_role_id", model.RoleId);
                cmd.Parameters.AddWithValue("@p_site", model.Site ?? "Default");
                cmd.Parameters.AddWithValue("@p_shift", model.Shift ?? "General");
                cmd.Parameters.AddWithValue("@p_location", model.Location ?? "Default");
                cmd.Parameters.AddWithValue("@p_created_by", 1);

                var userIdParam = new NpgsqlParameter("@p_user_id", NpgsqlTypes.NpgsqlDbType.Integer)
                {
                    Direction = ParameterDirection.Output,
                    Value = DBNull.Value
                };
                cmd.Parameters.Add(userIdParam);

                await cmd.ExecuteNonQueryAsync();

                int userId = Convert.ToInt32(userIdParam.Value);

                await transaction.CommitAsync();
                return userId;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error registering user");
                throw;
            }
        }

        public async Task<List<UsersList>> GetAllUsersAsync()
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            var sql = @"
                SELECT 
                    u.userid AS UserId,
                    u.employeeid AS EmployeeId,
                    u.fullname AS FullName,
                    u.username AS UserName,
                    u.email AS Email,
                    u.mobileno AS MobileNo,
                    u.departmentid AS DepartmentId,
                    d.department_name AS DepartmentName,
                    u.roleid AS RoleId,
                    r.rolename AS RoleName,
                    u.site AS Site,
                    u.shift AS Shift,
                    u.location AS Location,
                    u.isactive AS IsActive,
                    u.createddate AS CreatedDate
                FROM public.tbl_users u
                LEFT JOIN public.tbl_roles r ON u.roleid = r.roleid
                LEFT JOIN public.tbl_department d ON u.departmentid = d.department_id
                ORDER BY u.fullname";

            return (await connection.QueryAsync<UsersList>(sql)).ToList();
        }

        public async Task<RegisterModel?> GetUserById(int userId)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();
            var sql = @"SELECT * FROM public.fn_get_all_users() WHERE UserId = @UserId";
            return await connection.QueryFirstOrDefaultAsync<RegisterModel>(sql, new { UserId = userId });
        }

        public async Task<bool> UpdateUser(int userId, RegisterModel model)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();
            var sql = @"CALL public.sp_user_update(
                @UserId,
                @EmployeeId,
                @FullName,
                @UserName,
                @Email,
                @MobileNo,
                @DepartmentId,
                @RoleId,
                @Site,
                @Shift,
                @Location
            )";
            var rowsAffected = await connection.ExecuteAsync(sql, new
            {
                model.EmployeeId,
                model.FullName,
                model.UserName,
                model.Email,
                model.MobileNo,
                model.DepartmentId,
                model.RoleId,
                model.Site,
                model.Shift,
                model.Location,
                UserId = userId
            });

            return rowsAffected > 0;
        }

        public async Task<bool> DeleteUser(int userId)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();
            var sql = @"CALL public.sp_user_delete(@UserId)";
            await connection.ExecuteAsync(sql, new { UserId = userId });
            return true;
        }

        public async Task<bool> AddDepartment(CreateDepartment department)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();
            var sql = @"CALL public.sp_insert_department(
                @DepartmentName,
                @DepartmentContactPerson,
                @Designation,
                @MobileNo,
                @Email
            )";

            var rowsAffected = await connection.ExecuteAsync(sql, department);
            return rowsAffected > 0;
        }

        public async Task<Dictionary<int, int>> GetUserCountByRole()
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            try
            {
                var sql = @"
                    SELECT 
                        r.roleid, 
                        COUNT(u.userid) as usercount
                    FROM public.tbl_roles r
                    LEFT JOIN public.tbl_users u ON r.roleid = u.roleid
                    GROUP BY r.roleid
                    ORDER BY r.roleid";

                var result = await connection.QueryAsync(sql);

                var dictionary = new Dictionary<int, int>();
                foreach (var item in result)
                {
                    dictionary[(int)item.roleid] = (int)item.usercount;
                }

                return dictionary;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user count by role");
                return new Dictionary<int, int>();
            }
        }

        // ==================== FORM BUILDER METHODS ====================

        public List<UserDto> GetActiveUsers()
        {
            using var connection = CreateConnection();
            connection.Open();

            try
            {
                var users = connection.Query<UserDto>(@"
                    SELECT 
                        u.userid AS UserId, 
                        u.fullname AS FullName, 
                        u.email AS Email, 
                        u.username AS Username,
                        u.roleid AS RoleId,
                        u.departmentid AS DepartmentId,
                        u.employeeid AS EmployeeId,
                        r.rolename AS RoleName
                    FROM public.tbl_users u
                    LEFT JOIN public.tbl_roles r ON u.roleid = r.roleid
                    WHERE u.isactive = true 
                    ORDER BY u.fullname
                ").ToList();

                _logger.LogInformation($"Loaded {users.Count} active users with roles");
                return users;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading users");
                return new List<UserDto>();
            }
        }

        public List<Department> GetActiveDepartmentsForForm()
        {
            using var connection = CreateConnection();
            connection.Open();

            try
            {
                var departments = connection.Query<Department>(@"SELECT * FROM public.fn_get_active_departments();").ToList();
                _logger.LogInformation($"Loaded {departments.Count} active departments");
                return departments;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading departments");
                return new List<Department>();
            }
        }

        public async Task<int> CreateFormAsync(string title, string description, string createdBy, List<FormField> fields, bool isActive, int userId)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            using var transaction = await connection.BeginTransactionAsync();

            try
            {
                _logger.LogInformation($"Creating form - Title: {title}, UserId: {userId}, Fields: {fields?.Count ?? 0}");

                var fieldsJson = new List<object>();
                int order = 1;

                foreach (var field in fields)
                {
                    fieldsJson.Add(new
                    {
                        FieldName = field.FieldName,
                        FieldType = field.FieldType,
                        FieldOrder = order++,
                        IsRequired = field.IsRequired,
                        Placeholder = field.Placeholder,
                        Options = field.Options
                    });
                }

                var fieldsJsonB = JsonSerializer.Serialize(fieldsJson);

                string cleanName = Regex.Replace(title, @"[^a-zA-Z0-9\s]", "");
                cleanName = cleanName.Replace(" ", "_");
                cleanName = cleanName.ToLower();
                cleanName = Regex.Replace(cleanName, @"_+", "_");
                cleanName = cleanName.Trim('_');
                if (cleanName.Length > 50)
                {
                    cleanName = cleanName.Substring(0, 50);
                }
                var tableName = $"form_{cleanName}";

                string originalTableName = tableName;
                int counter = 1;
                var checkSql = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = @TableName";
                var exists = await connection.ExecuteScalarAsync<int>(checkSql, new { TableName = tableName }, transaction);

                while (exists > 0)
                {
                    tableName = $"{originalTableName}_{counter}";
                    exists = await connection.ExecuteScalarAsync<int>(checkSql, new { TableName = tableName }, transaction);
                    counter++;
                }

                var sql = @"
                    INSERT INTO public.tbl_forms 
                        (form_title, form_description, created_by, created_at, is_active, table_name, userid, fields_json)
                    VALUES 
                        (@FormTitle, @FormDescription, @CreatedBy, NOW(), @IsActive, @TableName, @UserId, @FieldsJson::jsonb)
                    RETURNING form_id";

                var formId = await connection.QuerySingleAsync<int>(sql, new
                {
                    FormTitle = title,
                    FormDescription = description,
                    CreatedBy = createdBy,
                    IsActive = isActive,
                    TableName = tableName,
                    UserId = userId,
                    FieldsJson = fieldsJsonB
                }, transaction);

                var createTableSql = $"CREATE TABLE IF NOT EXISTS public.{tableName} (" +
                    "id SERIAL PRIMARY KEY," +
                    "submitted_by_user_id INTEGER," +
                    "submitted_at TIMESTAMP DEFAULT NOW()";

                foreach (var field in fields)
                {
                    var columnName = Regex.Replace(field.FieldName, @"[^a-zA-Z0-9_]", "_");
                    createTableSql += $", {columnName} TEXT";
                }

                createTableSql += ")";

                await connection.ExecuteAsync(createTableSql, transaction: transaction);

                await transaction.CommitAsync();
                _logger.LogInformation($"Form {formId} created successfully");
                return formId;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating form");
                await transaction.RollbackAsync();
                throw;
            }
        }

        public List<FormSummary> GetForms(int? userId = null)
        {
            using var connection = CreateConnection();
            connection.Open();

            try
            {
                string sql = @"
                    SELECT 
                        form_id AS FormId,
                        form_title AS FormTitle,
                        form_description AS FormDescription,
                        created_by AS CreatedBy,
                        created_at AS CreatedAt,
                        is_active AS IsActive,
                        table_name AS TableName,
                        userid AS UserId
                    FROM public.tbl_forms
                    WHERE 1=1";

                if (userId.HasValue && userId.Value > 0)
                {
                    sql += " AND userid = @UserId";
                }

                sql += " ORDER BY created_at DESC";

                var forms = connection.Query<FormSummary>(sql, new { UserId = userId }).ToList();

                // Load form fields for each form
                foreach (var form in forms)
                {
                    form.FormFields = GetFormFields(form.FormId);
                }

                return forms;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting forms");
                return new List<FormSummary>();
            }
        }

        public List<FormSummary> GetFormsForUser(int userId)
        {
            using var connection = CreateConnection();
            connection.Open();

            try
            {
                var sql = @"
                    SELECT 
                        f.form_id AS FormId,
                        f.form_title AS FormTitle,
                        f.form_description AS FormDescription,
                        f.created_by AS CreatedBy,
                        f.created_at AS CreatedAt,
                        f.is_active AS IsActive,
                        f.table_name AS TableName,
                        f.userid AS UserId,
                        u.fullname AS AssignedToUserName
                    FROM public.tbl_forms f
                    LEFT JOIN public.tbl_users u ON f.userid = u.userid
                    WHERE f.userid = @UserId 
                    AND (f.is_active = true OR f.is_active IS NULL)
                    ORDER BY f.created_at DESC";

                var forms = connection.Query<FormSummary>(sql, new { UserId = userId }).ToList();

                // Load form fields for each form
                foreach (var form in forms)
                {
                    form.FormFields = GetFormFields(form.FormId);
                }

                _logger.LogInformation($"Loaded {forms.Count} forms for user {userId}");
                return forms;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting forms for user {UserId}", userId);
                return new List<FormSummary>();
            }
        }

        // SINGLE GetFormFields method - NO DUPLICATES
        public List<FormField> GetFormFields(int formId)
        {
            using var connection = CreateConnection();
            connection.Open();

            try
            {
                var fieldsJson = connection.QueryFirstOrDefault<string>(
                    @"SELECT fields_json::text FROM public.tbl_forms WHERE form_id = @formId",
                    new { formId });

                if (!string.IsNullOrEmpty(fieldsJson))
                {
                    var fields = JsonSerializer.Deserialize<List<FormField>>(fieldsJson);
                    if (fields != null && fields.Any())
                    {
                        _logger.LogInformation($"Loaded {fields.Count} fields from JSON for form {formId}");
                        return fields;
                    }
                }

                return new List<FormField>();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting form fields for form {formId}");
                return new List<FormField>();
            }
        }

        public FormSummary? GetFormById(int formId)
        {
            using var connection = CreateConnection();
            connection.Open();

            try
            {
                var sql = @"
                    SELECT 
                        f.form_id AS FormId,
                        f.form_title AS FormTitle,
                        f.form_description AS FormDescription,
                        f.created_by AS CreatedBy,
                        f.created_at AS CreatedAt,
                        f.is_active AS IsActive,
                        f.table_name AS TableName,
                        f.userid AS UserId,
                        u.fullname AS AssignedToUserName
                    FROM public.tbl_forms f
                    LEFT JOIN public.tbl_users u ON f.userid = u.userid
                    WHERE f.form_id = @FormId";

                var form = connection.QueryFirstOrDefault<FormSummary>(sql, new { FormId = formId });

                if (form != null)
                {
                    form.FormFields = GetFormFields(form.FormId);
                }

                return form;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting form by ID {FormId}", formId);
                return null;
            }
        }

        public void SaveFormData(int formId, Dictionary<string, string> values, int submittedByUserId)
        {
            using var connection = CreateConnection();
            connection.Open();

            using var transaction = connection.BeginTransaction();

            try
            {
                var tableName = connection.QueryFirstOrDefault<string>(
                    @"SELECT table_name FROM public.tbl_forms WHERE form_id = @formId",
                    new { formId }, transaction);

                if (string.IsNullOrEmpty(tableName))
                {
                    throw new Exception($"Form {formId} not found");
                }

                values.Remove("__RequestVerificationToken");
                values.Remove("FormId");
                values.Remove("TableName");

                var columns = new List<string> { "submitted_by_user_id" };
                var parameters = new List<string> { "@SubmittedByUserId" };
                var paramValues = new DynamicParameters();
                paramValues.Add("SubmittedByUserId", submittedByUserId);

                foreach (var kvp in values)
                {
                    // Clean column name - replace spaces and special chars with underscore
                    var columnName = Regex.Replace(kvp.Key, @"[^a-zA-Z0-9_]", "_");
                    columns.Add(columnName);

                    // Create a valid parameter name (no spaces, no special chars)
                    var paramName = $"@p_{columnName}";
                    parameters.Add(paramName);
                    paramValues.Add(paramName.TrimStart('@'), kvp.Value);
                }

                var insertSql = $"INSERT INTO public.{tableName} ({string.Join(", ", columns)}) VALUES ({string.Join(", ", parameters)})";
                connection.Execute(insertSql, paramValues, transaction);

                transaction.Commit();
                _logger.LogInformation($"Form data saved successfully for form {formId}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error saving form data for form {formId}");
                transaction.Rollback();
                throw;
            }
        }
        public bool DeleteForm(int formId)
        {
            using var connection = CreateConnection();
            connection.Open();

            using var transaction = connection.BeginTransaction();

            try
            {
                var form = connection.QueryFirstOrDefault<FormSummary>(
                    @"SELECT * FROM public.tbl_forms WHERE form_id = @formId",
                    new { formId }, transaction);

                if (form == null)
                {
                    _logger.LogWarning($"Form {formId} not found");
                    return false;
                }

                if (!string.IsNullOrEmpty(form.TableName))
                {
                    if (!Regex.IsMatch(form.TableName, @"^[a-zA-Z_][a-zA-Z0-9_]*$"))
                        throw new InvalidOperationException($"Invalid table name: {form.TableName}");

                    string dropTableSql = $"DROP TABLE IF EXISTS public.{form.TableName}";
                    connection.Execute(dropTableSql, transaction: transaction);
                    _logger.LogInformation($"Dropped table: {form.TableName}");
                }

                string deleteFormSql = "DELETE FROM public.tbl_forms WHERE form_id = @formId";
                connection.Execute(deleteFormSql, new { formId }, transaction);

                transaction.Commit();
                _logger.LogInformation($"Form '{form.FormTitle}' (ID: {formId}) deleted successfully");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting form {formId}");
                transaction.Rollback();
                throw;
            }
        }

        // ==================== ROLE PERMISSIONS ====================

        public async Task<List<RolePermission>> GetRolePermissions(int roleId)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            try
            {
                var sql = @"
                    SELECT 
                        module_name AS ModuleName,
                        can_view AS CanView,
                        can_create AS CanCreate,
                        can_modify AS CanModify,
                        can_delete AS CanDelete
                    FROM public.tbl_role_permissions
                    WHERE role_id = @RoleId";

                var permissions = (await connection.QueryAsync<RolePermission>(sql, new { RoleId = roleId })).ToList();

                if (!permissions.Any())
                {
                    return new List<RolePermission>
                    {
                        new RolePermission { ModuleName = "Manage Forms", CanView = false, CanCreate = false, CanModify = false, CanDelete = false },
                        new RolePermission { ModuleName = "User Management", CanView = false, CanCreate = false, CanModify = false, CanDelete = false }
                    };
                }

                return permissions;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting permissions for role {RoleId}", roleId);
                return new List<RolePermission>();
            }
        }

        public async Task<bool> UpdateRolePermissions(int roleId, List<RolePermission> permissions)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            using var transaction = await connection.BeginTransactionAsync();

            try
            {
                var deleteSql = "DELETE FROM public.tbl_role_permissions WHERE role_id = @RoleId";
                await connection.ExecuteAsync(deleteSql, new { RoleId = roleId }, transaction);

                foreach (var perm in permissions)
                {
                    var insertSql = @"
                        INSERT INTO public.tbl_role_permissions 
                            (role_id, module_name, can_view, can_create, can_modify, can_delete)
                        VALUES 
                            (@RoleId, @ModuleName, @CanView, @CanCreate, @CanModify, @CanDelete)";

                    await connection.ExecuteAsync(insertSql, new
                    {
                        RoleId = roleId,
                        ModuleName = perm.ModuleName,
                        CanView = perm.CanView,
                        CanCreate = perm.CanCreate,
                        CanModify = perm.CanModify,
                        CanDelete = perm.CanDelete
                    }, transaction);
                }

                await transaction.CommitAsync();
                _logger.LogInformation($"Permissions updated for role {roleId}");
                return true;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error updating permissions for role {RoleId}", roleId);
                return false;
            }
        }

        public async Task<RoleModel> CreateRole(RoleModel role)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            using var transaction = await connection.BeginTransactionAsync();

            try
            {
                var insertSql = @"
                    INSERT INTO public.tbl_roles (rolename, isactive)
                    VALUES (@rolename, @isactive)
                    RETURNING roleid";

                var roleId = await connection.ExecuteScalarAsync<int>(insertSql, new
                {
                    rolename = role.rolename,
                    isactive = true
                }, transaction);

                role.roleid = roleId;

                var defaultPermissions = new List<RolePermission>
                {
                    new RolePermission { ModuleName = "Manage Forms", CanView = false, CanCreate = false, CanModify = false, CanDelete = false },
                    new RolePermission { ModuleName = "User Management", CanView = false, CanCreate = false, CanModify = false, CanDelete = false }
                };

                foreach (var perm in defaultPermissions)
                {
                    var permSql = @"
                        INSERT INTO public.tbl_role_permissions 
                            (role_id, module_name, can_view, can_create, can_modify, can_delete)
                        VALUES 
                            (@RoleId, @ModuleName, @CanView, @CanCreate, @CanModify, @CanDelete)";

                    await connection.ExecuteAsync(permSql, new
                    {
                        RoleId = roleId,
                        ModuleName = perm.ModuleName,
                        CanView = perm.CanView,
                        CanCreate = perm.CanCreate,
                        CanModify = perm.CanModify,
                        CanDelete = perm.CanDelete
                    }, transaction);
                }

                await transaction.CommitAsync();
                _logger.LogInformation($"Role '{role.rolename}' created with ID {roleId}");
                return role;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error creating role");
                throw;
            }
        }

        public async Task<bool> DeleteRole(int roleId)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            using var transaction = await connection.BeginTransactionAsync();

            try
            {
                var deletePermsSql = "DELETE FROM public.tbl_role_permissions WHERE role_id = @RoleId";
                await connection.ExecuteAsync(deletePermsSql, new { RoleId = roleId }, transaction);

                var deleteRoleSql = "DELETE FROM public.tbl_roles WHERE roleid = @RoleId";
                var rowsAffected = await connection.ExecuteAsync(deleteRoleSql, new { RoleId = roleId }, transaction);

                await transaction.CommitAsync();
                _logger.LogInformation($"Role {roleId} deleted: {rowsAffected > 0}");
                return rowsAffected > 0;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Error deleting role {RoleId}", roleId);
                return false;
            }
        }

        public async Task<bool> HasUsersInRole(int roleId)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            try
            {
                var sql = "SELECT COUNT(*) FROM public.tbl_users WHERE roleid = @RoleId";
                var count = await connection.ExecuteScalarAsync<int>(sql, new { RoleId = roleId });
                return count > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking users in role {RoleId}", roleId);
                return true;
            }
        }

        public async Task<bool> HasModulePermission(int roleId, string moduleName, string permissionType)
        {
            using var connection = CreateConnection();
            await connection.OpenAsync();

            var sql = @"
                SELECT CASE 
                    WHEN @PermissionType = 'View' THEN can_view
                    WHEN @PermissionType = 'Create' THEN can_create
                    WHEN @PermissionType = 'Modify' THEN can_modify
                    WHEN @PermissionType = 'Delete' THEN can_delete
                    ELSE false
                END
                FROM public.tbl_role_permissions
                WHERE role_id = @RoleId AND module_name = @ModuleName";

            var hasPermission = await connection.ExecuteScalarAsync<bool>(sql, new
            {
                RoleId = roleId,
                ModuleName = moduleName,
                PermissionType = permissionType
            });

            return hasPermission;
        }
    }
}