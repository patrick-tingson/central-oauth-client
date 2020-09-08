using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace CentralizedOAuthClient.Extemtion
{
    public class AuthorizeUserAttribute : ActionFilterAttribute
    {
        private const string USER_RIGHTS = "rights";
        private const string USER_METHOD = "method";
        public Actions[] Actions { get; set; }
        public string Method { get; set; }

        private ContentResult ForbiddenResult = new ContentResult
        {
            Content = $"{HttpStatusCode.Forbidden}",
            StatusCode = (int)HttpStatusCode.Forbidden
        };

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            var userRights = context.HttpContext.User.Claims.Where(r => r.Type.Equals(USER_RIGHTS));

            if (userRights.Count() > 0)
            {
                var getMethodAndActionsForDebugging = userRights.Where(r => r.Value.ToLower().Contains("get") && r.Value.ToLower().Contains(Method));

                foreach (var actions in Actions)
                {
                    if (userRights.Any(r => r.Value.ToLower().Contains(actions.ToString().ToLower()) && r.Value.ToLower().Contains(Method)))
                    {
                        return;
                    }
                }
            }

            context.Result = ForbiddenResult;
        }

    }

    public class UserRights
    {
        public UserAllowedMethod Rights { get; set; }
    }

    public class UserAllowedMethod
    {
        public string Method { get; set; }
        public List<string> Actions { get; set; }
    }

    public enum Actions
    {
        get,
        add,
        update,
        delete,
        send_code
    }
}
