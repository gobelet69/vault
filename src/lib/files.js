import { HttpError } from "./http.js";

const EDITABLE_EXTENSIONS = new Set([
  "js",
  "jsx",
  "ts",
  "tsx",
  "py",
  "json",
  "md",
  "txt",
  "html",
  "css",
  "scss",
  "yaml",
  "yml",
  "xml",
  "sql",
  "sh",
  "go",
  "rs",
  "java",
  "c",
  "cpp",
  "h",
  "hpp",
  "toml",
]);

const MIME_BY_EXTENSION = {
  pdf: "application/pdf",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  gif: "image/gif",
  webp: "image/webp",
  svg: "image/svg+xml",
  txt: "text/plain; charset=utf-8",
  md: "text/markdown; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  jsx: "text/javascript; charset=utf-8",
  ts: "text/typescript; charset=utf-8",
  tsx: "text/typescript; charset=utf-8",
  html: "text/html; charset=utf-8",
  css: "text/css; charset=utf-8",
  json: "application/json; charset=utf-8",
  yaml: "application/yaml; charset=utf-8",
  yml: "application/yaml; charset=utf-8",
  xml: "application/xml; charset=utf-8",
  csv: "text/csv; charset=utf-8",
  mp4: "video/mp4",
  mov: "video/quicktime",
  avi: "video/x-msvideo",
  mp3: "audio/mpeg",
};

const LANGUAGE_BY_EXTENSION = {
  js: "javascript",
  jsx: "javascript",
  ts: "typescript",
  tsx: "typescript",
  py: "python",
  json: "json",
  md: "markdown",
  txt: "plaintext",
  html: "html",
  css: "css",
  scss: "scss",
  yaml: "yaml",
  yml: "yaml",
  xml: "xml",
  sql: "sql",
  sh: "shell",
  go: "go",
  rs: "rust",
  java: "java",
  c: "c",
  cpp: "cpp",
  h: "cpp",
  hpp: "cpp",
  toml: "toml",
};

export function extensionOf(fileKey) {
  const file = fileKey.split("/").pop() || "";
  const dot = file.lastIndexOf(".");
  return dot === -1 ? "" : file.slice(dot + 1).toLowerCase();
}

export function isEditableFile(fileKey) {
  return EDITABLE_EXTENSIONS.has(extensionOf(fileKey));
}

export function detectLanguage(fileKey) {
  return LANGUAGE_BY_EXTENSION[extensionOf(fileKey)] || "plaintext";
}

export function getMimeType(fileKey) {
  return MIME_BY_EXTENSION[extensionOf(fileKey)] || "application/octet-stream";
}

export function sanitizeFilename(value) {
  const clean = (value || "")
    .replace(/[^\x20-\x7E]/g, "")
    .replace(/[\\]/g, "/")
    .split("/")
    .filter(Boolean)
    .join("_")
    .trim();
  if (!clean) throw new HttpError(400, "Filename is required.");
  if (clean.startsWith(".")) throw new HttpError(400, "Filename cannot start with '.'.");
  if (clean.length > 255) throw new HttpError(400, "Filename is too long.");
  return clean;
}

export function sanitizeFolderPath(value) {
  const normalized = (value || "")
    .trim()
    .replace(/^\/+|\/+$/g, "")
    .split("/")
    .filter(Boolean)
    .join("/");
  if (normalized.includes("..")) throw new HttpError(400, "Invalid folder path.");
  return normalized;
}

export function joinFolderAndFile(folderPath, filename) {
  const folder = sanitizeFolderPath(folderPath);
  const file = sanitizeFilename(filename);
  return folder ? `${folder}/${file}` : file;
}

export function isFolderMetaKey(key) {
  return key.startsWith(".folder:");
}

export function isInternalVersionKey(key) {
  return key.startsWith(".versions/");
}

