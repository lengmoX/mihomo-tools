import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const REPO = 'XTLS/Xray-core';
const API_URL = `https://api.github.com/repos/${REPO}/releases/latest`;
const DEFAULT_TARGET_DIR = path.resolve(__dirname, '../xray');

async function downloadXray(targetDirInput) {
  const targetDir = targetDirInput ? path.resolve(targetDirInput) : DEFAULT_TARGET_DIR;
  
  console.log(`Target directory: ${targetDir}`);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  try {
    console.log(`Fetching latest release information from ${API_URL}...`);
    const response = await fetch(API_URL, {
      headers: {
        'User-Agent': 'xray-tools-downloader',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch release info: ${response.statusText} (${response.status})`);
    }

    const data = await response.json();
    console.log(`Latest release version found: ${data.name || data.tag_name}`);

    // Find the Windows 64-bit zip asset
    const asset = data.assets.find(
      (a) => a.name.toLowerCase() === 'xray-windows-64.zip'
    );

    if (!asset) {
      throw new Error(`Could not find Xray-windows-64.zip in the latest release assets.`);
    }

    const downloadUrl = asset.browser_download_url;
    console.log(`Found asset URL: ${downloadUrl}`);
    console.log(`Downloading ${asset.name} (${(asset.size / 1024 / 1024).toFixed(2)} MB)...`);

    const fileResponse = await fetch(downloadUrl);
    if (!fileResponse.ok) {
      throw new Error(`Failed to download asset: ${fileResponse.statusText}`);
    }

    const arrayBuffer = await fileResponse.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    const tempZipPath = path.join(targetDir, 'xray-temp.zip');
    fs.writeFileSync(tempZipPath, buffer);
    console.log(`Saved temporary archive to: ${tempZipPath}`);

    console.log(`Extracting archive using system tar...`);
    // tar works on modern Windows 10/11 and standard Unix systems out of the box
    try {
      execSync(`tar -xf "${tempZipPath}" -C "${targetDir}"`, { stdio: 'inherit' });
      console.log('Extraction completed successfully.');
    } catch (tarError) {
      console.error('Failed to extract using tar. Trying backup extraction methods...');
      throw tarError;
    } finally {
      // Clean up the temp zip file
      if (fs.existsSync(tempZipPath)) {
        fs.unlinkSync(tempZipPath);
        console.log('Cleaned up temporary archive.');
      }
    }

    // Verify critical files exist
    const criticalFiles = ['xray.exe', 'geoip.dat', 'geosite.dat'];
    const missingFiles = [];
    for (const file of criticalFiles) {
      const filePath = path.join(targetDir, file);
      if (!fs.existsSync(filePath)) {
        // tar might extract files in mixed/lowercase. Let's look for case variations
        const dirFiles = fs.readdirSync(targetDir);
        const matches = dirFiles.filter((f) => f.toLowerCase() === file.toLowerCase());
        if (matches.length > 0) {
          // Rename to lowercase standard for portability/consistency
          fs.renameSync(path.join(targetDir, matches[0]), filePath);
        } else {
          missingFiles.push(file);
        }
      }
    }

    if (missingFiles.length > 0) {
      console.warn(`Warning: Critical file(s) missing from target directory: ${missingFiles.join(', ')}`);
    } else {
      console.log('Xray Core is fully downloaded and verified in target directory.');
    }

  } catch (error) {
    console.error('Error occurred during Xray download:', error);
    process.exit(1);
  }
}

// Get target dir from CLI arguments if provided
const args = process.argv.slice(2);
downloadXray(args[0]);
