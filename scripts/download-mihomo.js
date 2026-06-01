import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';
import zlib from 'node:zlib';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const REPO = 'MetaCubeX/mihomo';
const API_URL = `https://api.github.com/repos/${REPO}/releases/latest`;
const DEFAULT_TARGET_DIR = path.resolve(__dirname, '../mihomo');

async function downloadMihomo(targetDirInput) {
  const targetDir = targetDirInput ? path.resolve(targetDirInput) : DEFAULT_TARGET_DIR;
  
  console.log(`Target directory: ${targetDir}`);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  // Determine current OS and architecture
  const platform = process.platform; // 'win32', 'darwin', 'linux'
  const arch = process.arch; // 'x64', 'arm64'
  console.log(`Detected platform: ${platform}, architecture: ${arch}`);

  try {
    console.log(`Fetching latest release information from ${API_URL}...`);
    const headers = { 'User-Agent': 'mihomo-tools-downloader' };
    // Use GITHUB_TOKEN if available to avoid API rate limits (60/hr → 5000/hr)
    const token = process.env.GITHUB_TOKEN;
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
      console.log('Using GITHUB_TOKEN for authenticated API access.');
    }

    const response = await fetch(API_URL, { headers });

    if (!response.ok) {
      throw new Error(`Failed to fetch release info: ${response.statusText} (${response.status})`);
    }

    const data = await response.json();
    const version = data.name || data.tag_name;
    console.log(`Latest release version found: ${version}`);

    // Match the correct asset name pattern based on OS and Arch
    let assetMatcher = null;
    let isZip = false;

    if (platform === 'win32') {
      isZip = true;
      if (arch === 'arm64') {
        assetMatcher = (name) => name.includes('windows-arm64') && name.endsWith('.zip') && !name.includes('go');
      } else {
        // Try compatible version first, fallback to standard amd64
        assetMatcher = (name) => name.includes('windows-amd64-compatible') && name.endsWith('.zip') && !name.includes('go');
      }
    } else if (platform === 'darwin') {
      isZip = false;
      if (arch === 'arm64') {
        assetMatcher = (name) => name.includes('darwin-arm64') && name.endsWith('.gz') && !name.includes('go');
      } else {
        assetMatcher = (name) => name.includes('darwin-amd64') && !name.includes('compatible') && name.endsWith('.gz') && !name.includes('go');
      }
    } else {
      // Fallback for Linux or others
      isZip = false;
      assetMatcher = (name) => name.includes('linux-amd64') && !name.includes('compatible') && name.endsWith('.gz') && !name.includes('go');
    }

    let asset = data.assets.find((a) => assetMatcher(a.name.toLowerCase()));
    
    // Fallback for windows if compatible not found
    if (!asset && platform === 'win32' && arch === 'x64') {
      console.log('Compatible Windows x64 asset not found, trying fallback standard amd64...');
      const fallbackMatcher = (name) => name.includes('windows-amd64') && !name.includes('compatible') && name.endsWith('.zip') && !name.includes('go');
      asset = data.assets.find((a) => fallbackMatcher(a.name.toLowerCase()));
    }

    if (!asset) {
      throw new Error(`Could not find a matching Mihomo release asset for platform ${platform} (${arch}).`);
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

    if (isZip) {
      // Windows ZIP extraction
      const tempZipPath = path.join(targetDir, 'mihomo-temp.zip');
      fs.writeFileSync(tempZipPath, buffer);
      console.log(`Saved temporary archive to: ${tempZipPath}`);

      console.log(`Extracting ZIP archive...`);
      try {
        // Use PowerShell Expand-Archive on Windows to avoid bsdtar
        // misinterpreting drive letters (e.g. D:) as remote host specs
        execSync(
          `powershell -NoProfile -Command "Expand-Archive -Path '${tempZipPath}' -DestinationPath '${targetDir}' -Force"`,
          { stdio: 'inherit' }
        );
        console.log('Extraction completed successfully.');
      } catch (extractError) {
        console.error('Failed to extract ZIP archive.');
        throw extractError;
      } finally {
        if (fs.existsSync(tempZipPath)) {
          fs.unlinkSync(tempZipPath);
          console.log('Cleaned up temporary archive.');
        }
      }

      // Rename extracted executable to mihomo.exe
      const files = fs.readdirSync(targetDir);
      let foundExe = false;
      for (const file of files) {
        if (file.toLowerCase().endsWith('.exe') && file.toLowerCase() !== 'mihomo.exe') {
          fs.renameSync(path.join(targetDir, file), path.join(targetDir, 'mihomo.exe'));
          foundExe = true;
          console.log(`Renamed ${file} to mihomo.exe`);
          break;
        } else if (file.toLowerCase() === 'mihomo.exe') {
          foundExe = true;
          break;
        }
      }

      if (!foundExe) {
        console.warn('Warning: Could not find any extracted executable ending with .exe');
      } else {
        console.log('Mihomo Core for Windows has been successfully downloaded and configured.');
      }
    } else {
      // macOS/Linux GZ extraction (single compressed binary file)
      console.log('Decompressing GZ archive using Node zlib...');
      const decompressed = zlib.gunzipSync(buffer);
      const binaryName = platform === 'win32' ? 'mihomo.exe' : 'mihomo';
      const outputPath = path.join(targetDir, binaryName);
      
      fs.writeFileSync(outputPath, decompressed);
      console.log(`Saved decompressed binary to: ${outputPath}`);

      // Set executable permission (chmod 755)
      fs.chmodSync(outputPath, 0o755);
      console.log(`Set executable permissions (chmod +x) for ${outputPath}`);
      console.log('Mihomo Core has been successfully downloaded and configured.');
    }

  } catch (error) {
    console.error('Error occurred during Mihomo core download:', error);
    process.exit(1);
  }
}

// Get target dir from CLI arguments if provided
const args = process.argv.slice(2);
downloadMihomo(args[0]);
