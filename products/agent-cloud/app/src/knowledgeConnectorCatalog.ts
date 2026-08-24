export type KnowledgeConnectorProvider = "google-drive" | "onedrive" | "sharepoint" | "notion" | "dropbox" | "confluence" | "web" | "s3" | "azure-blob" | "github" | "database";

export type KnowledgeConnectorManifest = {
  provider: KnowledgeConnectorProvider;
  label: string;
  family: "Workspace" | "Docs" | "Storage" | "Engineering" | "Database";
  auth: "OAuth 2.0" | "Secret reference" | "Public / optional secret";
  locatorLabel: string;
  locatorPlaceholder: string;
  scopes: readonly string[];
};

export const knowledgeConnectorCatalog: readonly KnowledgeConnectorManifest[] = [
  { provider: "google-drive", label: "Google Drive", family: "Workspace", auth: "OAuth 2.0", locatorLabel: "Folder or shared-drive ID", locatorPlaceholder: "1AbC… or shared-drive://operations", scopes: ["drive.readonly"] },
  { provider: "onedrive", label: "Microsoft OneDrive", family: "Workspace", auth: "OAuth 2.0", locatorLabel: "Drive and folder path", locatorPlaceholder: "drive-id:/Operations", scopes: ["Files.Read.All", "offline_access"] },
  { provider: "sharepoint", label: "SharePoint", family: "Workspace", auth: "OAuth 2.0", locatorLabel: "Site and library", locatorPlaceholder: "site-id:/Shared Documents/Policies", scopes: ["Sites.Read.All", "offline_access"] },
  { provider: "notion", label: "Notion", family: "Docs", auth: "OAuth 2.0", locatorLabel: "Page or database ID", locatorPlaceholder: "notion-page-or-database-id", scopes: ["read_content"] },
  { provider: "dropbox", label: "Dropbox", family: "Storage", auth: "OAuth 2.0", locatorLabel: "Folder path", locatorPlaceholder: "/Team/Operations", scopes: ["files.content.read"] },
  { provider: "confluence", label: "Confluence", family: "Docs", auth: "OAuth 2.0", locatorLabel: "Site and space key", locatorPlaceholder: "acme.atlassian.net/wiki:OPS", scopes: ["read:content:confluence"] },
  { provider: "web", label: "Web knowledge", family: "Docs", auth: "Public / optional secret", locatorLabel: "Allowed root URL", locatorPlaceholder: "https://docs.example.com/handbook", scopes: ["read-only crawl"] },
  { provider: "s3", label: "Amazon S3", family: "Storage", auth: "Secret reference", locatorLabel: "Bucket and prefix", locatorPlaceholder: "s3://company-knowledge/operations/", scopes: ["s3:GetObject", "s3:ListBucket"] },
  { provider: "azure-blob", label: "Azure Blob", family: "Storage", auth: "Secret reference", locatorLabel: "Container and prefix", locatorPlaceholder: "azure-blob://knowledge/operations/", scopes: ["Storage Blob Data Reader"] },
  { provider: "github", label: "GitHub", family: "Engineering", auth: "OAuth 2.0", locatorLabel: "Repository and path", locatorPlaceholder: "owner/repo:docs/", scopes: ["contents:read"] },
  { provider: "database", label: "Database / warehouse", family: "Database", auth: "Secret reference", locatorLabel: "Read-only dataset reference", locatorPlaceholder: "postgres://knowledge_view or warehouse.dataset", scopes: ["read-only view"] },
];
