# fraudshield-backend
Multi-agent AI pipeline for real-time UPI fraud detection, investigation, and response. Built on Azure (OpenAI, Cosmos DB, Event Hub, Functions, Bot Service). Detects scams across Hindi, Hinglish, English, Tamil, Bengali with automated 1930 complaint filing and community blacklisting.

## Deployment

The project deploys to Azure Functions via GitHub Actions (`.github/workflows/deploy.yml`). The workflow triggers on pushes to `main` and uses the Azure Functions **publish profile** for authentication.

### Required GitHub Secrets

| Secret | Description |
|---|---|
| `AZURE_FUNCTIONAPP_PUBLISH_PROFILE` | Publish profile XML downloaded from the Azure Function App |

### Setup

1. In the Azure Portal, navigate to your Function App (`fraudshield-api`).
2. Click **Get publish profile** to download the `.PublishSettings` file.
3. Copy the entire XML content of the file.
4. Add it as a repository secret named `AZURE_FUNCTIONAPP_PUBLISH_PROFILE` in **Settings > Secrets and variables > Actions**.
