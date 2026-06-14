import { scanTarget } from "./scanner/index.js";

const target = process.argv[2] || "https://example.com";
const report = await scanTarget(target);

console.log(JSON.stringify(report, null, 2));
