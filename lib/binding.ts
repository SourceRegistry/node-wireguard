/**
 * @author A.P.A. Slaa (a.p.a.slaa@projectsource.nl) ProjectSource V.O.F.
 */

import fs from 'fs';
import path from 'path';

const platform = process.platform;
const arch = process.arch;

const base_name = "node-wireguard"
const is_package = __dirname.includes("node_modules");

function devAddonPath(): string {
    const mode = process.env["NODE_ENV"] === "development" ? "Debug" : "Release";
    if (mode === "Debug") {
        console.warn("!!!RUNNING IN DEVELOPMENT MODE!!!");
    }
    return path.join(__dirname, '..', 'build', mode, `${base_name}.node`);
}

function packagedAddonPath(): string | undefined {
    const archToTriplet: Record<string, string> = {
        x64: 'x86_64-linux-gnu',
        arm64: 'aarch64-linux-gnu',
    };
    const triplet = platform === 'linux' ? archToTriplet[arch] : undefined;
    return triplet ? path.join(__dirname, '..', 'bin', triplet, `${base_name}.node`) : undefined;
}

let addonPath: string | undefined;
if (is_package) {
    // Prefer a shipped prebuild (bin/<triplet>/); fall back to whatever
    // `npm install`'s gypfile-triggered node-gyp rebuild produced locally
    // (build/Release/) when no matching prebuild was published.
    const packaged = packagedAddonPath();
    addonPath = packaged && fs.existsSync(packaged) ? packaged : devAddonPath();
} else {
    addonPath = devAddonPath();
}

if (!addonPath || !fs.existsSync(addonPath)) {
    throw new Error(
        `node-wireguard: no native addon found at ${addonPath} (platform=${platform}, arch=${arch}). ` +
            `Run \`npm run build\` (development) or \`npm run package\` (to stage a prebuild) first.`,
    );
}

export default require(addonPath)
