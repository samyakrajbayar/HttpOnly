export function parseTarget(rawTarget) {
  const input = rawTarget.trim();
  const normalized = input.match(/^https?:\/\//i) ? input : `https://${input}`;
  let url;

  try {
    url = new URL(normalized);
  } catch {
    const error = new Error("Enter a valid URL or GitHub repository link.");
    error.statusCode = 400;
    throw error;
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    const error = new Error("Only HTTP and HTTPS targets are supported.");
    error.statusCode = 400;
    throw error;
  }

  const githubRepo = parseGitHubRepo(url);
  if (githubRepo) {
    return {
      type: "github",
      display: `https://github.com/${githubRepo.owner}/${githubRepo.repo}`,
      url,
      ...githubRepo
    };
  }

  return {
    type: "url",
    display: url.toString(),
    url
  };
}

function parseGitHubRepo(url) {
  if (url.hostname.toLowerCase() !== "github.com") {
    return null;
  }

  const [owner, repoWithSuffix] = url.pathname.split("/").filter(Boolean);
  if (!owner || !repoWithSuffix) {
    return null;
  }

  const repo = repoWithSuffix.replace(/\.git$/i, "");
  return { owner, repo };
}
