#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const marker = /<!-- deploy-button:start -->[\s\S]*?<!-- deploy-button:end -->/;
const input = process.argv[2];

if (!input || process.argv.length !== 3) {
  console.error("Usage: node scripts/set-deploy-button.mjs <public GitHub or GitLab repository URL>");
  process.exit(2);
}

function parseRepositoryUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Provide a complete HTTPS GitHub or GitLab repository URL.");
  }

  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error("The repository URL must use HTTPS and cannot include credentials, a query, or a fragment.");
  }

  const host = url.hostname.toLowerCase();
  if (host !== "github.com" && host !== "gitlab.com") {
    throw new Error("Only public repositories hosted on github.com or gitlab.com are supported.");
  }

  let segments;
  try {
    segments = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
  } catch {
    throw new Error("The repository URL contains invalid path encoding.");
  }

  if (segments.length < 2 || segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw new Error("The URL must point to a repository, such as https://github.com/owner/repository.");
  }

  segments[segments.length - 1] = segments.at(-1).replace(/\.git$/i, "");
  if (!segments.at(-1)) {
    throw new Error("The repository name is missing from the URL.");
  }

  if (host === "github.com" && segments.length !== 2) {
    throw new Error("A GitHub repository URL must contain exactly an owner and repository name.");
  }

  const encodedPath = segments.map(encodeURIComponent).join("/");
  return {
    host,
    apiUrl: host === "github.com"
      ? `https://api.github.com/repos/${encodedPath}`
      : `https://gitlab.com/api/v4/projects/${encodeURIComponent(segments.join("/"))}`,
  };
}

async function verifyPublicRepository(repository) {
  let response;
  try {
    response = await fetch(repository.apiUrl, {
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": "cloudflare-monitor-deploy-button-setup",
      },
      signal: AbortSignal.timeout(10_000),
    });
  } catch (error) {
    throw new Error(`Could not verify the repository: ${error.message}`);
  }

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error("The repository was not found or is private. The deploy button was left unchanged.");
    }
    throw new Error(`Repository verification returned HTTP ${response.status}. The deploy button was left unchanged.`);
  }

  const details = await response.json();
  const isPublic = repository.host === "github.com"
    ? details.private === false
    : details.visibility === "public";

  if (!isPublic) {
    throw new Error("The repository is not public. The deploy button was left unchanged.");
  }

  const verifiedUrl = repository.host === "github.com" ? details.html_url : details.web_url;
  if (typeof verifiedUrl !== "string") {
    throw new Error("The public repository response did not include its canonical URL.");
  }

  return verifiedUrl.replace(/\.git$/i, "");
}

try {
  const repository = parseRepositoryUrl(input);
  const verifiedUrl = await verifyPublicRepository(repository);
  const readmePath = fileURLToPath(new URL("../README.md", import.meta.url));
  const readme = await readFile(readmePath, "utf8");
  const matches = readme.match(/<!-- deploy-button:start -->/g) ?? [];
  if (matches.length !== 1 || !marker.test(readme)) {
    throw new Error("README.md must contain exactly one deploy-button marker pair.");
  }

  const deployUrl = new URL("https://deploy.workers.cloudflare.com/");
  deployUrl.searchParams.set("url", verifiedUrl);
  const button = [
    "<!-- deploy-button:start -->",
    `[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](${deployUrl.href})`,
    "<!-- deploy-button:end -->",
  ].join("\n");

  await writeFile(readmePath, readme.replace(marker, button), "utf8");
  console.log(`Added the Cloudflare deploy button for the verified public repository: ${verifiedUrl}`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
