package github

import authsec "github.com/authsec-ai/sdk-authsec/packages/go-sdk"

func DefaultPolicy() authsec.ToolPolicy {
	return authsec.StaticPolicy{
		"list_issues":              {AnyOfScopes: []string{"issues:read"}},
		"get_issue":                {AnyOfScopes: []string{"issues:read"}},
		"create_issue":             {AnyOfScopes: []string{"issues:write"}},
		"add_issue_comment":        {AnyOfScopes: []string{"issues:write"}},
		"list_pull_requests":       {AnyOfScopes: []string{"pull_requests:read"}},
		"get_pull_request":         {AnyOfScopes: []string{"pull_requests:read"}},
		"create_pull_request":      {AnyOfScopes: []string{"pull_requests:write"}},
		"merge_pull_request":       {AnyOfScopes: []string{"pull_requests:write"}},
		"get_file_contents":        {AnyOfScopes: []string{"repos:read"}},
		"search_code":              {AnyOfScopes: []string{"repos:read"}},
		"list_commits":             {AnyOfScopes: []string{"repos:read"}},
		"create_or_update_file":    {AnyOfScopes: []string{"repos:write"}},
		"delete_file":              {AnyOfScopes: []string{"repos:write"}},
		"create_branch":            {AnyOfScopes: []string{"repos:write"}},
		"fork_repository":          {AnyOfScopes: []string{"repos:write"}},
		"create_repository":        {AnyOfScopes: []string{"admin:write"}},
		"get_latest_release":       {AnyOfScopes: []string{"repos:read"}},
		"list_workflows":           {AnyOfScopes: []string{"actions:read"}},
		"run_workflow":             {AnyOfScopes: []string{"actions:write"}},
		"get_workflow_run_logs":    {AnyOfScopes: []string{"actions:read"}},
		"list_code_scanning":       {AnyOfScopes: []string{"security:read"}},
		"list_secret_scanning":     {AnyOfScopes: []string{"security:read"}},
		"list_security_advisories": {AnyOfScopes: []string{"security:read"}},
	}
}
