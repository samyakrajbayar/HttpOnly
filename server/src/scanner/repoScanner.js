import semver from "semver";
import { createFinding } from "./risk.js";
import { fetchWithTimeout } from "./http.js";

const githubHeaders = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28"
};

export async function scanRepository(target) {
  const repo = await githubJson(`https://api.github.com/repos/${target.owner}/${target.repo}`);
  const tree = await githubJson(`https://api.github.com/repos/${target.owner}/${target.repo}/git/trees/${repo.default_branch}?recursive=1`);
  const files = tree.tree || [];
  const findings = [];

  findings.push(...scanRepositoryHygiene(files));

  const manifests = findManifests(files);
  const dependencies = [];

  for (const manifest of manifests.slice(0, 6)) {
    const manifestFindings = await scanManifest(target, repo.default_branch, manifest.path);
    findings.push(...manifestFindings.findings);
    dependencies.push(...manifestFindings.dependencies);
  }

  if (manifests.length === 0) {
    findings.push(createFinding({
      title: "No supported dependency manifest found",
      description: "The scanner did not find package.json or requirements.txt in the repository tree.",
      severity: "info",
      category: "Dependencies",
      recommendation: "Add a supported manifest or extend the scanner for this project's package manager."
    }));
  }

  return {
    status: {
      repository: repo.full_name,
      defaultBranch: repo.default_branch,
      visibility: repo.private ? "private" : "public",
      stars: repo.stargazers_count,
      openIssues: repo.open_issues_count
    },
    findings,
    assets: {
      manifests: manifests.map((manifest) => manifest.path),
      dependencies,
      repositoryFilesChecked: files.length
    }
  };
}

async function scanManifest(target, branch, path) {
  const rawUrl = `https://raw.githubusercontent.com/${target.owner}/${target.repo}/${branch}/${path}`;
  const response = await fetchWithTimeout(rawUrl, {}, 10000);

  if (!response.ok) {
    return {
      findings: [createFinding({
        title: `Could not read ${path}`,
        description: "The dependency manifest was found in the tree but could not be downloaded.",
        severity: "info",
        category: "Dependencies",
        recommendation: "Check repository permissions or try again later."
      })],
      dependencies: []
    };
  }

  const text = await response.text();

  if (path.endsWith("package.json")) {
    return scanPackageJson(path, text);
  }

  if (path.endsWith("requirements.txt")) {
    return scanRequirements(path, text);
  }

  return { findings: [], dependencies: [] };
}

async function scanPackageJson(path, text) {
  const findings = [];
  const dependencies = [];
  let manifest;

  try {
    manifest = JSON.parse(text);
  } catch {
    return {
      findings: [createFinding({
        title: `${path} is not valid JSON`,
        description: "The manifest could not be parsed.",
        severity: "medium",
        category: "Dependencies",
        recommendation: "Fix JSON syntax so dependency tooling and scanners can inspect it."
      })],
      dependencies
    };
  }

  const allDeps = {
    ...(manifest.dependencies || {}),
    ...(manifest.devDependencies || {})
  };
  const entries = Object.entries(allDeps).slice(0, 45);

  for (const [name, range] of entries) {
    const current = semver.minVersion(range);
    const dependency = {
      ecosystem: "npm",
      manifest: path,
      name,
      declared: range,
      current: current?.version || null,
      latest: null,
      status: "unknown",
      severity: "info"
    };

    if (isLooseRange(range)) {
      dependency.status = "unpinned";
      dependency.severity = "medium";
      findings.push(createFinding({
        title: `${name} uses a loose npm version range`,
        description: "Loose ranges make builds less reproducible and can unexpectedly pull new code.",
        severity: "medium",
        category: "Dependencies",
        evidence: `${name}@${range} in ${path}`,
        recommendation: "Pin production dependencies or use a lockfile committed to source control."
      }));
    }

    const latest = await fetchNpmLatest(name);
    dependency.latest = latest;

    if (current && latest && semver.valid(latest) && semver.lt(current, latest)) {
      const severity = classifyVersionLag(current.version, latest);
      dependency.status = "outdated";
      dependency.severity = severity;
      findings.push(createFinding({
        title: `${name} is behind the latest npm release`,
        description: `Declared version resolves near ${current.version}, while npm latest is ${latest}.`,
        severity,
        category: "Dependencies",
        evidence: `${name}: ${range} -> ${latest}`,
        recommendation: "Review the package changelog, update the dependency, and run the project's test suite."
      }));
    } else if (latest) {
      dependency.status = dependency.status === "unknown" ? "current" : dependency.status;
    }

    dependencies.push(dependency);
  }

  if (entries.length === 0) {
    findings.push(createFinding({
      title: `${path} has no listed npm dependencies`,
      description: "The manifest was readable but no dependencies or devDependencies were found.",
      severity: "info",
      category: "Dependencies"
    }));
  }

  return { findings, dependencies };
}

async function scanRequirements(path, text) {
  const findings = [];
  const dependencies = [];
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));

  for (const line of lines.slice(0, 45)) {
    const exact = line.match(/^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)$/);
    const loose = line.match(/^([A-Za-z0-9_.-]+)\s*([<>=~!]+)\s*(.+)$/);
    const name = exact?.[1] || loose?.[1] || line.split(/[<>=~! ]/)[0];
    const declared = exact?.[2] || loose?.[3] || null;
    const latest = await fetchPyPiLatest(name);
    const dependency = {
      ecosystem: "pypi",
      manifest: path,
      name,
      declared: declared || line,
      current: exact?.[2] || null,
      latest,
      status: "unknown",
      severity: "info"
    };

    if (!exact) {
      dependency.status = "unpinned";
      dependency.severity = "medium";
      findings.push(createFinding({
        title: `${name} is not exactly pinned`,
        description: "Non-exact Python requirements can make builds less reproducible.",
        severity: "medium",
        category: "Dependencies",
        evidence: `${line} in ${path}`,
        recommendation: "Pin critical production dependencies with == and maintain them with a lock or update workflow."
      }));
    }

    if (exact && latest && compareLooseVersions(exact[2], latest) < 0) {
      dependency.status = "outdated";
      dependency.severity = "medium";
      findings.push(createFinding({
        title: `${name} is behind the latest PyPI release`,
        description: `Pinned version is ${exact[2]}, while PyPI latest is ${latest}.`,
        severity: "medium",
        category: "Dependencies",
        evidence: `${name}: ${exact[2]} -> ${latest}`,
        recommendation: "Review release notes, update the package, and run tests."
      }));
    } else if (latest) {
      dependency.status = dependency.status === "unknown" ? "current" : dependency.status;
    }

    dependencies.push(dependency);
  }

  return { findings, dependencies };
}

function scanRepositoryHygiene(files) {
  const paths = new Set(files.map((file) => file.path.toLowerCase()));
  const findings = [];

  if ([...paths].some((path) => path.endsWith(".env") || path.includes("/.env."))) {
    findings.push(createFinding({
      title: "Environment file appears to be committed",
      description: "Files named .env often contain secrets or deployment configuration.",
      severity: "high",
      category: "Repository Hygiene",
      recommendation: "Remove committed secrets, rotate exposed values, and keep only sanitized .env.example files."
    }));
  }

  if ([...paths].some((path) => path.endsWith(".pem") || path.endsWith(".key") || path.endsWith("id_rsa"))) {
    findings.push(createFinding({
      title: "Potential private key material found",
      description: "The repository tree contains filenames commonly used for private keys.",
      severity: "critical",
      category: "Repository Hygiene",
      recommendation: "Remove key files from history where possible and rotate the affected credentials immediately."
    }));
  }

  if (!paths.has("security.md") && !paths.has(".github/security.md")) {
    findings.push(createFinding({
      title: "Security policy file is missing",
      description: "A SECURITY.md file helps researchers report vulnerabilities responsibly.",
      severity: "low",
      category: "Repository Hygiene",
      recommendation: "Add SECURITY.md with supported versions and a vulnerability reporting contact."
    }));
  }

  if (!paths.has(".github/dependabot.yml") && !paths.has(".github/dependabot.yaml")) {
    findings.push(createFinding({
      title: "Dependabot configuration is missing",
      description: "Automated dependency update checks reduce the chance of stale vulnerable packages.",
      severity: "medium",
      category: "Repository Hygiene",
      recommendation: "Add .github/dependabot.yml for the package ecosystems used by this repository."
    }));
  }

  if (paths.has("package.json") && !paths.has("package-lock.json") && !paths.has("yarn.lock") && !paths.has("pnpm-lock.yaml")) {
    findings.push(createFinding({
      title: "JavaScript lockfile is missing",
      description: "A package.json file is present without a common lockfile.",
      severity: "medium",
      category: "Dependencies",
      recommendation: "Commit a lockfile so installs are reproducible and audit tools inspect exact versions."
    }));
  }

  return findings;
}

function findManifests(files) {
  return files
    .filter((file) => file.type === "blob")
    .filter((file) => file.path.endsWith("package.json") || file.path.endsWith("requirements.txt"))
    .filter((file) => !file.path.includes("node_modules/") && !file.path.includes("vendor/"))
    .sort((a, b) => a.path.localeCompare(b.path));
}

async function githubJson(url) {
  const response = await fetchWithTimeout(url, { headers: githubHeaders }, 12000);

  if (!response.ok) {
    const error = new Error(response.status === 404
      ? "GitHub repository not found or not public."
      : `GitHub API request failed with status ${response.status}.`);
    error.statusCode = response.status === 404 ? 404 : 502;
    throw error;
  }

  return response.json();
}

async function fetchNpmLatest(name) {
  try {
    const response = await fetchWithTimeout(`https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}/latest`, {}, 8000);
    if (!response.ok) return null;
    const data = await response.json();
    return data.version || null;
  } catch {
    return null;
  }
}

async function fetchPyPiLatest(name) {
  try {
    const response = await fetchWithTimeout(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, {}, 8000);
    if (!response.ok) return null;
    const data = await response.json();
    return data.info?.version || null;
  } catch {
    return null;
  }
}

function classifyVersionLag(current, latest) {
  const currentVersion = semver.parse(current);
  const latestVersion = semver.parse(latest);

  if (!currentVersion || !latestVersion) return "medium";
  if (latestVersion.major > currentVersion.major) return "high";
  if (latestVersion.minor > currentVersion.minor) return "medium";
  return "low";
}

function isLooseRange(range) {
  return ["*", "latest", "x"].includes(String(range).trim().toLowerCase());
}

function compareLooseVersions(a, b) {
  const left = a.split(/[.-]/).map((value) => Number.parseInt(value, 10) || 0);
  const right = b.split(/[.-]/).map((value) => Number.parseInt(value, 10) || 0);
  const length = Math.max(left.length, right.length);

  for (let index = 0; index < length; index += 1) {
    if ((left[index] || 0) > (right[index] || 0)) return 1;
    if ((left[index] || 0) < (right[index] || 0)) return -1;
  }

  return 0;
}
