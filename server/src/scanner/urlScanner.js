import * as cheerio from "cheerio";
import { createFinding } from "./risk.js";
import { fetchWithTimeout, readTextWithLimit } from "./http.js";

const requiredHeaders = [
  {
    key: "content-security-policy",
    name: "Content-Security-Policy",
    severity: "high",
    recommendation: "Add a restrictive Content-Security-Policy to limit script, frame, and asset sources."
  },
  {
    key: "x-frame-options",
    name: "X-Frame-Options",
    severity: "medium",
    recommendation: "Send X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."
  },
  {
    key: "x-content-type-options",
    name: "X-Content-Type-Options",
    severity: "medium",
    recommendation: "Send X-Content-Type-Options: nosniff."
  },
  {
    key: "referrer-policy",
    name: "Referrer-Policy",
    severity: "low",
    recommendation: "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin."
  },
  {
    key: "permissions-policy",
    name: "Permissions-Policy",
    severity: "low",
    recommendation: "Use Permissions-Policy to disable browser features the app does not need."
  }
];

export async function scanUrl(target) {
  const response = await fetchWithTimeout(target.url);
  const body = await readTextWithLimit(response);
  const headers = Object.fromEntries(response.headers.entries());
  const findings = [];
  const $ = cheerio.load(body || "");

  findings.push(...scanSecurityHeaders(target.url, headers));
  findings.push(...scanCookies(headers));
  findings.push(...scanHtmlSurface($, body, target.url));
  findings.push(...await scanReflectedParameters(target.url));

  return {
    status: {
      httpStatus: response.status,
      finalUrl: response.url,
      contentType: headers["content-type"] || "unknown"
    },
    findings,
    assets: {
      headers: summarizeHeaders(headers),
      forms: summarizeForms($),
      linksChecked: $("a[href]").length,
      scriptsDetected: $("script[src], script:not([src])").length
    }
  };
}

function scanSecurityHeaders(url, headers) {
  const findings = [];

  for (const header of requiredHeaders) {
    if (!headers[header.key]) {
      findings.push(createFinding({
        title: `${header.name} header is missing`,
        description: `The response does not include ${header.name}, which weakens browser-side protections.`,
        severity: header.severity,
        category: "Security Headers",
        recommendation: header.recommendation
      }));
    }
  }

  if (url.protocol === "https:" && !headers["strict-transport-security"]) {
    findings.push(createFinding({
      title: "Strict-Transport-Security header is missing",
      description: "HTTPS responses should instruct browsers to keep using encrypted connections.",
      severity: "high",
      category: "Security Headers",
      recommendation: "Send Strict-Transport-Security with an appropriate max-age and includeSubDomains after validating HTTPS coverage."
    }));
  }

  const csp = headers["content-security-policy"];
  if (csp && /unsafe-inline|unsafe-eval/i.test(csp)) {
    findings.push(createFinding({
      title: "Content-Security-Policy allows unsafe script behavior",
      description: "The CSP contains unsafe-inline or unsafe-eval, reducing its protection against XSS.",
      severity: "medium",
      category: "Security Headers",
      evidence: csp,
      recommendation: "Replace unsafe script directives with nonces, hashes, or strict dynamic script loading."
    }));
  }

  if (headers["x-powered-by"]) {
    findings.push(createFinding({
      title: "Technology fingerprint header exposed",
      description: "X-Powered-By reveals framework or runtime details that are useful to attackers.",
      severity: "low",
      category: "Information Exposure",
      evidence: `X-Powered-By: ${headers["x-powered-by"]}`,
      recommendation: "Disable X-Powered-By in the web framework or reverse proxy."
    }));
  }

  if (headers["access-control-allow-origin"] === "*") {
    findings.push(createFinding({
      title: "CORS allows every origin",
      description: "A wildcard Access-Control-Allow-Origin policy can expose APIs to untrusted browser origins.",
      severity: "medium",
      category: "CORS",
      evidence: "Access-Control-Allow-Origin: *",
      recommendation: "Restrict CORS to trusted origins and avoid allowing credentials with broad policies."
    }));
  }

  return findings;
}

function scanCookies(headers) {
  const setCookie = headers["set-cookie"];
  if (!setCookie) return [];

  const cookies = splitCookies(setCookie);
  const findings = [];

  for (const cookie of cookies) {
    const [name] = cookie.split("=");
    const lower = cookie.toLowerCase();

    if (!lower.includes("httponly")) {
      findings.push(createFinding({
        title: `Cookie ${name} is missing HttpOnly`,
        description: "Client-side scripts may be able to read this cookie if an XSS issue exists.",
        severity: "medium",
        category: "Cookies",
        evidence: name,
        recommendation: "Add the HttpOnly attribute to sensitive session and authentication cookies."
      }));
    }

    if (!lower.includes("secure")) {
      findings.push(createFinding({
        title: `Cookie ${name} is missing Secure`,
        description: "The cookie can be sent over unencrypted HTTP connections.",
        severity: "medium",
        category: "Cookies",
        evidence: name,
        recommendation: "Add the Secure attribute to cookies that should only travel over HTTPS."
      }));
    }

    if (!lower.includes("samesite")) {
      findings.push(createFinding({
        title: `Cookie ${name} is missing SameSite`,
        description: "The cookie does not declare cross-site request behavior.",
        severity: "low",
        category: "Cookies",
        evidence: name,
        recommendation: "Set SameSite=Lax or SameSite=Strict unless cross-site usage is required."
      }));
    }
  }

  return findings;
}

function scanHtmlSurface($, body, url) {
  const findings = [];

  if (url.protocol === "https:" && /\s(?:src|href)=["']http:\/\//i.test(body)) {
    findings.push(createFinding({
      title: "Potential mixed content detected",
      description: "The page references HTTP assets from an HTTPS page.",
      severity: "medium",
      category: "Transport Security",
      recommendation: "Load scripts, stylesheets, images, and links over HTTPS."
    }));
  }

  $("form").each((index, element) => {
    const form = $(element);
    const method = (form.attr("method") || "get").toLowerCase();
    const inputCount = form.find("input, textarea, select").length;
    const textInputs = form.find("input[type='text'], input:not([type]), input[type='search'], input[type='email'], input[type='url'], textarea").length;

    if (textInputs > 0) {
      findings.push(createFinding({
        title: `User input form detected (${method.toUpperCase()})`,
        description: "The page contains user-controllable text inputs. Server-side validation and output encoding should be verified.",
        severity: method === "get" ? "medium" : "low",
        category: "XSS Surface",
        evidence: `Form ${index + 1}: ${inputCount} input(s), ${textInputs} text-like input(s)`,
        recommendation: "Validate input on the server and HTML-encode reflected values by output context."
      }));
    }
  });

  return findings;
}

async function scanReflectedParameters(url) {
  const findings = [];
  const marker = `secscan_marker_${Date.now()}`;
  const probeUrl = new URL(url.toString());

  if ([...probeUrl.searchParams.keys()].length === 0) {
    probeUrl.searchParams.set("secscan_probe", marker);
  } else {
    for (const key of [...probeUrl.searchParams.keys()]) {
      probeUrl.searchParams.set(key, marker);
    }
  }

  try {
    const response = await fetchWithTimeout(probeUrl, {}, 8000);
    const body = await readTextWithLimit(response, 400000);

    if (body.includes(marker)) {
      findings.push(createFinding({
        title: "Reflected query parameter detected",
        description: "A harmless scanner marker was reflected in the response. This is not proof of XSS, but it is a useful place to verify output encoding.",
        severity: "medium",
        category: "XSS Surface",
        evidence: probeUrl.toString(),
        recommendation: "Ensure reflected query values are encoded for their HTML, JavaScript, URL, or attribute context."
      }));
    }
  } catch {
    findings.push(createFinding({
      title: "Reflection probe could not be completed",
      description: "The scanner could not complete a harmless query-parameter reflection check.",
      severity: "info",
      category: "Scanner",
      recommendation: "Retry the scan or test reflected parameters manually if this route accepts user input."
    }));
  }

  return findings;
}

function summarizeHeaders(headers) {
  const names = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
    "server",
    "x-powered-by"
  ];

  return names.map((name) => ({
    name,
    value: headers[name] || null,
    present: Boolean(headers[name])
  }));
}

function summarizeForms($) {
  const forms = [];

  $("form").each((index, element) => {
    const form = $(element);
    forms.push({
      index: index + 1,
      method: (form.attr("method") || "get").toUpperCase(),
      action: form.attr("action") || "current page",
      inputCount: form.find("input, textarea, select").length
    });
  });

  return forms;
}

function splitCookies(setCookieHeader) {
  return setCookieHeader.split(/,(?=\s*[^;,]+=)/g).map((cookie) => cookie.trim()).filter(Boolean);
}
