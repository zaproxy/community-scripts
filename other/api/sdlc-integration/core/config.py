zap_url = "http://localhost:8080"

max_duration = 1 # Number of minutes to spider and active-scan for (default 1)

# target_auth can be ignored if we're not using 'scanAsUser()' (for spider or ascan)
target_auth = {
	"login_url": "https://www.example.com/profile/signin.html",
	"user": "foo@example.com",
	"pw": "bar"
}

# Create prefilled credentials for Jira bugtacker
jira_auth = {
	"user": "foo",
	"pw": "bar" # or getpass.getpass()
} 
# Set URL and project ID for Jira bugtacker
jira_base_url = "https://jira.example.com/rest/api/2/issue"
jira_project_key = "foobar"

