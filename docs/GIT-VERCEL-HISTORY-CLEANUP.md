# Hiding Git & Vercel History — Reference Guide

> Saved at user request (Aug 18, 2026). This is the plan for cleaning commit
> history before/after final submission so judges see a clean repository.

## 1. Hiding Git Commit History

Squash the entire history into a single clean "Initial Commit" so no one can
see the middle steps:

```bash
# Create a temporary orphan branch (no parent history)
git checkout --orphan latest_branch

# Add all project files
git add -A

# Commit everything as one clean commit
git commit -am "Initial commit"

# Delete the old branch
git branch -D main   # or: git branch -D master

# Rename the temporary branch to main
git branch -m main

# Force-push the clean history
git push -f origin main
```

### Alternative: Switch the repository to Private

Change the GitHub / GitLab / Bitbucket repository visibility from Public to
Private — this restricts the entire history to you and invited collaborators.

## 2. Hiding / Deleting Vercel Deployment History

Vercel has no single "hide history" toggle — handle it per deployment:

### Delete specific deployments permanently

1. Log into the Vercel Dashboard and select the project.
2. Open the **Deployments** tab.
3. Click the specific deployment to clear.
4. Click the three-dots (**...**) menu on the deployment overview.
5. Select **Delete**.

### Prevent Git deployments from posting publicly

1. Project → **Settings** tab.
2. Click **Git** in the sidebar.
3. Scroll to the **GitHub Comments** or **deployment_status** events sections.
4. Disable the toggles to mute external tracking.

### Deploy manually via CLI (no Git linkage)

Disconnect the Git repository from Vercel and deploy manually — this pushes
code without uploading commit messages or linking back to the remote history:

```bash
vercel --prod
```
