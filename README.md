# fraudshield-backend
Multi-agent AI pipeline for real-time UPI fraud detection, investigation, and response. Built on Azure (OpenAI, Cosmos DB, Event Hub, Functions, Bot Service). Detects scams across Hindi, Hinglish, English, Tamil, Bengali with automated 1930 complaint filing and community blacklisting.

## Deployment

The project deploys to Azure Functions via GitHub Actions (`.github/workflows/deploy.yml`). The workflow triggers on pushes to `main` and uses OpenID Connect (OIDC) federated credentials for passwordless authentication with Azure.

### Required GitHub Secrets

| Secret | Description |
|---|---|
| `AZURE_CLIENT_ID` | Application (client) ID of the Azure AD app registration |
| `AZURE_TENANT_ID` | Directory (tenant) ID of the Azure AD tenant |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |
| `AZURE_RESOURCE_GROUP` | Azure resource group containing the Function App |

### Azure Setup for OIDC

1. Register an application in Azure Active Directory.
2. Add a federated credential for the GitHub Actions workflow (set the subject to `repo:fraudshield-india/fraudshield-backend:ref:refs/heads/main`).
3. Assign the application the required roles (e.g., Contributor) on the target resource group.
4. Add the secrets listed above to the repository's **Settings > Secrets and variables > Actions**.
