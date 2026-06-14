export async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      redirect: "follow",
      ...options,
      headers: {
        "User-Agent": "LightweightVulnerabilityScanner/1.0",
        Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        ...(options.headers || {})
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

export async function readTextWithLimit(response, limitBytes = 900000) {
  if (!response.body) {
    return "";
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let output = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    received += value.length;
    if (received > limitBytes) {
      output += decoder.decode(value.slice(0, Math.max(0, value.length - (received - limitBytes))), {
        stream: false
      });
      break;
    }

    output += decoder.decode(value, { stream: true });
  }

  return output;
}
