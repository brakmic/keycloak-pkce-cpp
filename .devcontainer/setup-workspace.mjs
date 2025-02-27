import fs from "fs";
import path from "path";

// Workspace file path
const workspaceFilePath = "/workspace/dev.code-workspace";

// Ensure the directory for the workspace file exists
const dirPath = path.dirname(workspaceFilePath);
if (!fs.existsSync(dirPath)) {
  fs.mkdirSync(dirPath, { recursive: true });
}

// Define the workspace configuration
const workspaceConfig = {
  folders: [
    {
      name: "DevContainer Workspace",
      path: "/workspace"
    },
    {
      name: "Host Workspace",
      path: "/host_workspace"
    }
  ],
  settings: {}
};

// Write the workspace file
fs.writeFileSync(workspaceFilePath, JSON.stringify(workspaceConfig, null, 2));
console.log(`Workspace file created: ${workspaceFilePath}`);
