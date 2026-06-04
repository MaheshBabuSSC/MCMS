using CMS.Models;
using CMS.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CMS.Controllers
{
    [Authorize]
    [Route("Admin")]
    public class AdminController : Controller
    {
        private readonly IAdminService _adminService;
        private readonly ILogger<AdminController> _logger;

        public AdminController(IAdminService adminService, ILogger<AdminController> logger)
        {
            _adminService = adminService;
            _logger = logger;
        }

        // ==================== HELPER METHOD ====================

        private async Task<bool> HasPermission(string moduleName, string permissionType)
        {
            var roleIdClaim = User.FindFirstValue("RoleId");
            if (string.IsNullOrEmpty(roleIdClaim)) return false;

            int roleId = int.Parse(roleIdClaim);
            return await _adminService.HasModulePermission(roleId, moduleName, permissionType);
        }

        // ==================== USER CREATION ====================

        [HttpGet("UserCreation")]
        public async Task<IActionResult> UserCreation()
        {
            if (!await HasPermission("User Management", "Create"))
            {
                TempData["ErrorMessage"] = "You don't have permission to create users";
                return RedirectToAction("FormsList");
            }

            var model = new RegisterModel
            {
                Roles = await _adminService.GetActiveRoles(),
                Departments = await _adminService.GetActiveDepartments()
            };
            return View("~/Views/Admin/UserCreation.cshtml", model);
        }

        [HttpPost("UserCreation")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UserCreation(RegisterModel model)
        {
            if (!await HasPermission("User Management", "Create"))
            {
                TempData["ErrorMessage"] = "You don't have permission to create users";
                return RedirectToAction("FormsList");
            }

            try
            {
                if (!ModelState.IsValid)
                {
                    model.Roles = await _adminService.GetActiveRoles();
                    model.Departments = await _adminService.GetActiveDepartments();
                    return View("~/Views/Admin/UserCreation.cshtml", model);
                }

                if (model.RoleId <= 0)
                {
                    ViewBag.Error = "Please select a role!";
                    model.Roles = await _adminService.GetActiveRoles();
                    model.Departments = await _adminService.GetActiveDepartments();
                    return View("~/Views/Admin/UserCreation.cshtml", model);
                }

                if (model.DepartmentId <= 0)
                {
                    ViewBag.Error = "Please select a department!";
                    model.Roles = await _adminService.GetActiveRoles();
                    model.Departments = await _adminService.GetActiveDepartments();
                    return View("~/Views/Admin/UserCreation.cshtml", model);
                }

                var createdBy = User.Identity?.Name ?? "Admin";
                var userId = await _adminService.RegisterUser(model, createdBy);

                if (userId > 0)
                {
                    TempData["SuccessMessage"] = $"User '{model.FullName}' registered successfully!";

                    var newModel = new RegisterModel
                    {
                        Roles = await _adminService.GetActiveRoles(),
                        Departments = await _adminService.GetActiveDepartments()
                    };
                    return View("~/Views/Admin/UserCreation.cshtml", newModel);
                }
                else
                {
                    ViewBag.Error = "Registration failed! Please try again.";
                    model.Roles = await _adminService.GetActiveRoles();
                    model.Departments = await _adminService.GetActiveDepartments();
                    return View("~/Views/Admin/UserCreation.cshtml", model);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user");
                ViewBag.Error = $"Error: {ex.Message}";
                model.Roles = await _adminService.GetActiveRoles();
                model.Departments = await _adminService.GetActiveDepartments();
                return View("~/Views/Admin/UserCreation.cshtml", model);
            }
        }

        // ==================== USER LIST ====================

        [HttpGet("UserList")]
        public async Task<IActionResult> UserList()
        {
            if (!await HasPermission("User Management", "View"))
            {
                TempData["ErrorMessage"] = "You don't have permission to view users";
                return RedirectToAction("FormsList");
            }

            var users = await _adminService.GetAllUsersAsync();
            return View("~/Views/Admin/UserList.cshtml", users);
        }

        // ==================== DEPARTMENT MANAGEMENT ====================

        [HttpGet("AddDepartment")]
        public async Task<IActionResult> AddDepartment()
        {
            if (!await HasPermission("User Management", "Create"))
            {
                TempData["ErrorMessage"] = "You don't have permission to add departments";
                return RedirectToAction("FormsList");
            }

            return View("~/Views/Admin/AddDepartment.cshtml");
        }

        [HttpPost("AddDepartment")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AddDepartment(CreateDepartment department)
        {
            if (!await HasPermission("User Management", "Create"))
            {
                TempData["ErrorMessage"] = "You don't have permission to add departments";
                return RedirectToAction("FormsList");
            }

            if (ModelState.IsValid)
            {
                var result = await _adminService.AddDepartment(department);
                if (result)
                {
                    TempData["SuccessMessage"] = "Department added successfully!";
                    return RedirectToAction("AddDepartment");
                }
                else
                {
                    ViewBag.ErrorMessage = "Failed to add department.";
                }
            }
            return View("~/Views/Admin/AddDepartment.cshtml", department);
        }

        // ==================== ROLES MANAGEMENT ====================

        [HttpGet("Roles")]
        public async Task<IActionResult> Roles()
        {
            if (!await HasPermission("User Management", "View"))
            {
                TempData["ErrorMessage"] = "You don't have permission to view roles";
                return RedirectToAction("FormsList");
            }

            var roles = await _adminService.GetActiveRoles();
            var userCounts = await _adminService.GetUserCountByRole();

            ViewBag.UserCounts = userCounts;
            return View("~/Views/Admin/Roles.cshtml", roles);
        }

        // ==================== FORM BUILDER ====================

        [HttpGet("FormBuilder")]
        public async Task<IActionResult> FormBuilder()
        {
            if (!await HasPermission("Manage Forms", "Create"))
            {
                TempData["ErrorMessage"] = "You don't have permission to create forms";
                return RedirectToAction("FormsList");
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
            ViewBag.Users = users;

            return View("~/Views/Admin/FormBuilder.cshtml", model);
        }

        [HttpPost("FormBuilder/Create")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateForm([FromForm] CreateFormRequest request)
        {
            if (!await HasPermission("Manage Forms", "Create"))
            {
                TempData["ErrorMessage"] = "You don't have permission to create forms";
                return RedirectToAction("FormsList");
            }

            try
            {
                request.CreatedBy = User.Identity?.Name ?? "Admin";
                request.Fields ??= new List<FormField>();

                if (request.UserId <= 0)
                {
                    ModelState.AddModelError("UserId", "Please select a user to assign this form");
                    var users = _adminService.GetActiveUsers();
                    ViewBag.Users = users;
                    var departments = _adminService.GetActiveDepartmentsForForm();
                    ViewBag.Departments = departments;
                    TempData["ErrorMessage"] = "Please select a user to assign this form";
                    return View("~/Views/Admin/FormBuilder.cshtml", request);
                }

                if (string.IsNullOrWhiteSpace(request.FormTitle))
                {
                    ModelState.AddModelError("FormTitle", "Form title is required");
                    var users = _adminService.GetActiveUsers();
                    ViewBag.Users = users;
                    var departments = _adminService.GetActiveDepartmentsForForm();
                    ViewBag.Departments = departments;
                    TempData["ErrorMessage"] = "Form title is required";
                    return View("~/Views/Admin/FormBuilder.cshtml", request);
                }

                foreach (var field in request.Fields)
                {
                    if (string.IsNullOrWhiteSpace(field.FieldName))
                    {
                        ModelState.AddModelError("Fields", "All fields must have labels");
                        var users = _adminService.GetActiveUsers();
                        ViewBag.Users = users;
                        var departments = _adminService.GetActiveDepartmentsForForm();
                        ViewBag.Departments = departments;
                        TempData["ErrorMessage"] = "All fields must have labels";
                        return View("~/Views/Admin/FormBuilder.cshtml", request);
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

                TempData["SuccessMessage"] = $"Form '{request.FormTitle}' saved successfully!";
                return RedirectToAction("FormBuilder");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating form");
                TempData["ErrorMessage"] = $"Error creating form: {ex.Message}";
                var users = _adminService.GetActiveUsers();
                ViewBag.Users = users;
                var departments = _adminService.GetActiveDepartmentsForForm();
                ViewBag.Departments = departments;
                return View("~/Views/Admin/FormBuilder.cshtml", request);
            }
        }

        // ==================== FORMS LIST ====================

        [HttpGet("FormsList")]
        public async Task<IActionResult> FormsListView()
        {
            var userIdClaim = User.FindFirstValue("UserId");
            var roleName = User.FindFirstValue("RoleName");

            if (string.IsNullOrEmpty(userIdClaim))
            {
                TempData["ErrorMessage"] = "User not authenticated";
                return RedirectToAction("Index", "Auth");
            }

            int userId = int.Parse(userIdClaim);

            // Check permission using helper
            bool canViewAllForms = await HasPermission("Manage Forms", "View");

            List<FormSummary> forms;

            if (canViewAllForms)
            {
                forms = _adminService.GetForms();
                ViewBag.IsAdmin = true;
                ViewBag.PageTitle = "All Forms";
                ViewBag.PageSubtitle = "Complete list of all forms in the system";
                ViewBag.UserRoleBadge = "Administrator Access";
            }
            else
            {
                forms = _adminService.GetFormsForUser(userId);
                ViewBag.IsAdmin = false;
                ViewBag.PageTitle = "Form List";
                ViewBag.PageSubtitle = "Forms assigned specifically to you";
                ViewBag.UserRoleBadge = "User Access";
            }

            ViewBag.UserRole = roleName;
            ViewBag.UserName = User.Identity?.Name;

            return View("~/Views/Admin/FormsList.cshtml", forms);
        }






        // ==================== SUBMIT FORM ====================

        [HttpGet("SubmitForm/{id}")]
        public async Task<IActionResult> SubmitForm(int id)
        {
            try
            {
                var userIdClaim = User.FindFirstValue("UserId");
                if (string.IsNullOrEmpty(userIdClaim))
                {
                    TempData["ErrorMessage"] = "User not authenticated";
                    return RedirectToAction("FormsList");
                }

                int userId = int.Parse(userIdClaim);

                var forms = _adminService.GetForms();
                var form = forms.FirstOrDefault(f => f.FormId == id);

                if (form == null)
                {
                    TempData["ErrorMessage"] = $"Form with ID {id} not found";
                    return RedirectToAction("FormsList");
                }

                if (!form.IsActive)
                {
                    TempData["ErrorMessage"] = "This form is currently inactive";
                    return RedirectToAction("FormsList");
                }

                // Check permission using helper
                bool hasViewPermission = await HasPermission("Manage Forms", "View");

                if (!hasViewPermission && form.UserId != userId)
                {
                    TempData["ErrorMessage"] = "You don't have permission to submit this form";
                    return RedirectToAction("FormsList");
                }

                var formFields = _adminService.GetFormFields(id);

                var viewModel = new DynamicFormViewModel
                {
                    FormId = form.FormId,
                    FormTitle = form.FormTitle,
                    FormDescription = form.FormDescription,
                    TableName = form.TableName,
                    Fields = formFields.Select(f => new DynamicFormFieldViewModel
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

                ViewData["Title"] = form.FormTitle;
                return View("~/Views/Admin/FormSubmit.cshtml", viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading form");
                TempData["ErrorMessage"] = $"Error loading form: {ex.Message}";
                return RedirectToAction("FormsList");
            }
        }

        [HttpPost("SubmitFormData/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SubmitFormData(int id)
        {
            try
            {
                var userIdClaim = User.FindFirstValue("UserId");
                if (string.IsNullOrEmpty(userIdClaim))
                {
                    TempData["ErrorMessage"] = "User not authenticated";
                    return RedirectToAction("SubmitForm", new { id });
                }

                int userId = int.Parse(userIdClaim);

                var forms = _adminService.GetForms();
                var form = forms.FirstOrDefault(f => f.FormId == id);

                if (form == null)
                {
                    TempData["ErrorMessage"] = $"Form with ID {id} not found";
                    return RedirectToAction("SubmitForm", new { id });
                }

                // Check permission using helper
                bool hasViewPermission = await HasPermission("Manage Forms", "View");

                if (!hasViewPermission && form.UserId != userId)
                {
                    TempData["ErrorMessage"] = "You don't have permission to submit this form";
                    return RedirectToAction("SubmitForm", new { id });
                }

                var data = new Dictionary<string, string>();

                foreach (var key in Request.Form.Keys)
                {
                    if (key != "__RequestVerificationToken" && key != "FormId" && key != "TableName" && !key.StartsWith("file_"))
                    {
                        data[key] = Request.Form[key].ToString();
                    }
                }

                string imagesFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", "images");
                string audioFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", "audio");
                string videoFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", "videos");

                if (!Directory.Exists(imagesFolder)) Directory.CreateDirectory(imagesFolder);
                if (!Directory.Exists(audioFolder)) Directory.CreateDirectory(audioFolder);
                if (!Directory.Exists(videoFolder)) Directory.CreateDirectory(videoFolder);

                if (Request.Form.Files != null && Request.Form.Files.Any())
                {
                    foreach (var file in Request.Form.Files)
                    {
                        if (file != null && file.Length > 0)
                        {
                            string fileType = "others";
                            string uploadsFolder = imagesFolder;
                            string relativePath = "";

                            if (file.ContentType.StartsWith("image/"))
                            {
                                fileType = "images";
                                uploadsFolder = imagesFolder;
                            }
                            else if (file.ContentType.StartsWith("audio/"))
                            {
                                fileType = "audio";
                                uploadsFolder = audioFolder;
                            }
                            else if (file.ContentType.StartsWith("video/"))
                            {
                                fileType = "videos";
                                uploadsFolder = videoFolder;
                            }

                            string fileExtension = Path.GetExtension(file.FileName);
                            if (string.IsNullOrEmpty(fileExtension))
                            {
                                if (file.ContentType.StartsWith("image/")) fileExtension = ".jpg";
                                else if (file.ContentType.StartsWith("audio/")) fileExtension = ".webm";
                                else if (file.ContentType.StartsWith("video/")) fileExtension = ".webm";
                                else fileExtension = ".bin";
                            }

                            string uniqueFileName = $"{Guid.NewGuid()}_{DateTime.Now:yyyyMMddHHmmss}{fileExtension}";
                            string filePath = Path.Combine(uploadsFolder, uniqueFileName);

                            using (var stream = new FileStream(filePath, FileMode.Create))
                            {
                                await file.CopyToAsync(stream);
                            }

                            relativePath = $"/uploads/{fileType}/{uniqueFileName}";
                            string fieldName = file.Name.Replace("file_", "");
                            data[fieldName] = relativePath;

                            _logger.LogInformation($"File saved: {relativePath} for field {fieldName}");
                        }
                    }
                }

                int submittedByUserId = userId;
                _adminService.SaveFormData(id, data, submittedByUserId);

                TempData["SuccessMessage"] = "Form submitted successfully!";
                return RedirectToAction("SubmitForm", new { id });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error submitting form: {FormId}", id);
                TempData["ErrorMessage"] = $"Error submitting form: {ex.Message}";
                return RedirectToAction("SubmitForm", new { id });
            }
        }

        // ==================== FORM DELETE ====================

        [HttpPost("DeleteForm/{id}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteForm(int id)
        {
            if (!await HasPermission("Manage Forms", "Delete"))
            {
                TempData["ErrorMessage"] = "You don't have permission to delete forms";
                return RedirectToAction("FormsList");
            }

            try
            {
                var forms = _adminService.GetForms();
                var form = forms.FirstOrDefault(f => f.FormId == id);

                if (form == null)
                {
                    TempData["ErrorMessage"] = $"Form with ID {id} not found";
                    return RedirectToAction("FormsList");
                }

                bool deleted = _adminService.DeleteForm(id);

                if (deleted)
                {
                    TempData["SuccessMessage"] = $"Form '{form.FormTitle}' deleted successfully!";
                }
                else
                {
                    TempData["ErrorMessage"] = $"Failed to delete form '{form.FormTitle}'";
                }

                return RedirectToAction("FormsList");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting form: {FormId}", id);
                TempData["ErrorMessage"] = $"Error deleting form: {ex.Message}";
                return RedirectToAction("FormsList");
            }
        }

        // ==================== VIEW SUBMISSIONS ====================

        //[HttpGet("ViewSubmissions/{formId}")]
        //public async Task<IActionResult> ViewSubmissions(int formId)
        //{
        //    if (!await HasPermission("Manage Forms", "View"))
        //    {
        //        TempData["ErrorMessage"] = "You don't have permission to view submissions";
        //        return RedirectToAction("FormsList");
        //    }

        //    try
        //    {
        //        var forms = _adminService.GetForms();
        //        var form = forms.FirstOrDefault(f => f.FormId == formId);

        //        if (form == null)
        //        {
        //            TempData["ErrorMessage"] = $"Form with ID {formId} not found";
        //            return RedirectToAction("FormsList");
        //        }

        //        var submissions = _adminService.GetFormSubmissions(formId, form.TableName);
        //        var formFields = _adminService.GetFormFields(formId);

        //        ViewBag.FormTitle = form.FormTitle;
        //        ViewBag.TableName = form.TableName;
        //        ViewBag.FormFields = formFields;
        //        ViewBag.FormId = formId;

        //        return View("~/Views/Admin/ViewSubmissions.cshtml", submissions);
        //    }
        //    catch (Exception ex)
        //    {
        //        _logger.LogError(ex, "Error loading submissions");
        //        TempData["ErrorMessage"] = $"Error loading submissions: {ex.Message}";
        //        return RedirectToAction("FormsList");
        //    }
        //}

        #region Role Permissions APIs

        [HttpGet("Roles/{roleId}/Permissions")]
        public async Task<ActionResult<List<RolePermission>>> GetRolePermissions(int roleId)
        {
            if (!await HasPermission("User Management", "View"))
            {
                return StatusCode(403, new { message = "You don't have permission to view role permissions" });
            }

            try
            {
                var permissions = await _adminService.GetRolePermissions(roleId);
                return Ok(permissions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting permissions for role {RoleId}", roleId);
                return StatusCode(500, new { message = "Error retrieving permissions", error = ex.Message });
            }
        }

        [HttpPut("Roles/{roleId}/Permissions")]
        public async Task<IActionResult> UpdateRolePermissions(int roleId, [FromBody] List<RolePermission> permissions)
        {
            if (!await HasPermission("User Management", "Modify"))
            {
                return StatusCode(403, new { message = "You don't have permission to update role permissions" });
            }

            try
            {
                if (permissions == null || !permissions.Any())
                    return BadRequest(new { message = "Permissions data is required" });

                var result = await _adminService.UpdateRolePermissions(roleId, permissions);
                if (result)
                    return Ok(new { success = true, message = "Permissions updated successfully" });

                return BadRequest(new { message = "Failed to update permissions" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating permissions for role {RoleId}", roleId);
                return StatusCode(500, new { message = "Error updating permissions", error = ex.Message });
            }
        }

        [HttpPost("Roles")]
        public async Task<ActionResult<RoleModel>> CreateRole([FromBody] CreateRoleRequest request)
        {
            if (!await HasPermission("User Management", "Create"))
            {
                return StatusCode(403, new { message = "You don't have permission to create roles" });
            }

            try
            {
                if (string.IsNullOrEmpty(request.RoleName))
                    return BadRequest(new { message = "Role name is required" });

                var role = new RoleModel { rolename = request.RoleName };
                var result = await _adminService.CreateRole(role);
                return Ok(new { success = true, message = $"Role '{request.RoleName}' created", roleId = result.roleid });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating role");
                return StatusCode(500, new { message = "Error creating role", error = ex.Message });
            }
        }

        [HttpDelete("Roles/{id}")]
        public async Task<IActionResult> DeleteRole(int id)
        {
            if (!await HasPermission("User Management", "Delete"))
            {
                return StatusCode(403, new { message = "You don't have permission to delete roles" });
            }

            try
            {
                var hasUsers = await _adminService.HasUsersInRole(id);
                if (hasUsers)
                    return BadRequest(new { message = "Cannot delete role with assigned users" });

                var result = await _adminService.DeleteRole(id);
                if (result)
                    return Ok(new { success = true, message = "Role deleted successfully" });

                return NotFound(new { message = "Role not found" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting role {RoleId}", id);
                return StatusCode(500, new { message = "Error deleting role", error = ex.Message });
            }
        }

        [HttpGet("api/Roles/{roleId}/HasPermission")]
        public async Task<ActionResult<bool>> HasModulePermission(int roleId, string moduleName, string permissionType)
        {
            try
            {
                var hasPermission = await _adminService.HasModulePermission(roleId, moduleName, permissionType);
                return Ok(hasPermission);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking permission");
                return Ok(false);
            }
        }

        #endregion
    }
}