import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rootDir = path.resolve(__dirname, '..');
const versionFilePath = path.join(rootDir, 'version.txt');
const packageJsonPath = path.join(rootDir, 'package.json');
const tauriConfPath = path.join(rootDir, 'src-tauri/tauri.conf.json');

const dryRun = process.argv.includes('--dry-run');

function runCommand(command) {
  console.log(`> ${command}`);
  if (dryRun) {
    console.log(`[Dry-Run] Skipped executing command: ${command}`);
    return '';
  }
  try {
    return execSync(command, { cwd: rootDir, encoding: 'utf8' }).trim();
  } catch (error) {
    console.error(`Error running command "${command}":`, error.message);
    process.exit(1);
  }
}

async function release() {
  console.log(`Starting release process... ${dryRun ? '(DRY RUN MODE)' : ''}`);

  // 1. Read version.txt
  if (!fs.existsSync(versionFilePath)) {
    console.error(`Error: version.txt not found at ${versionFilePath}`);
    process.exit(1);
  }

  const version = fs.readFileSync(versionFilePath, 'utf8').trim();
  console.log(`Target version: "${version}"`);

  // 2. Validate SemVer format
  const semverRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$/;
  if (!semverRegex.test(version)) {
    console.error(`Error: Version "${version}" is not a valid Semantic Versioning (SemVer) string.`);
    process.exit(1);
  }

  // 3. Update package.json
  if (fs.existsSync(packageJsonPath)) {
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    if (pkg.version !== version) {
      console.log(`Updating package.json version from ${pkg.version} to ${version}...`);
      pkg.version = version;
      if (!dryRun) {
        fs.writeFileSync(packageJsonPath, JSON.stringify(pkg, null, 2) + '\n');
      }
      console.log(`Updated package.json successfully.`);
    } else {
      console.log(`package.json is already up to date (${pkg.version}).`);
    }
  } else {
    console.warn(`Warning: package.json not found at ${packageJsonPath}`);
  }

  // 4. Update src-tauri/tauri.conf.json
  if (fs.existsSync(tauriConfPath)) {
    const conf = JSON.parse(fs.readFileSync(tauriConfPath, 'utf8'));
    if (conf.version !== version) {
      console.log(`Updating tauri.conf.json version from ${conf.version} to ${version}...`);
      conf.version = version;
      if (!dryRun) {
        fs.writeFileSync(tauriConfPath, JSON.stringify(conf, null, 2) + '\n');
      }
      console.log(`Updated tauri.conf.json successfully.`);
    } else {
      console.log(`tauri.conf.json is already up to date (${conf.version}).`);
    }
  } else {
    console.warn(`Warning: tauri.conf.json not found at ${tauriConfPath}`);
  }

  // 5. Git workflow
  try {
    // Verify inside a git repo
    runCommand('git rev-parse --is-inside-work-tree');
    
    // Resolve current branch
    const currentBranch = dryRun ? 'main' : runCommand('git rev-parse --abbrev-ref HEAD');
    console.log(`Current active branch: ${currentBranch}`);

    console.log('Staging files...');
    runCommand('git add version.txt package.json src-tauri/tauri.conf.json');

    console.log('Creating version release commit...');
    runCommand(`git commit -m "chore: release v${version}"`);

    console.log(`Creating git tag v${version}...`);
    runCommand(`git tag -a v${version} -m "Release v${version}"`);

    console.log(`Pushing commit to branch: ${currentBranch}...`);
    runCommand(`git push origin ${currentBranch}`);

    console.log(`Pushing release tag v${version} to trigger GitHub Actions...`);
    runCommand(`git push origin v${version}`);

    console.log(`\nSuccess! Version bumped, tagged, and pushed to GitHub.`);
    if (dryRun) {
      console.log(`[Dry-Run Note] No actual changes were committed, tagged, or pushed to your repository.`);
    } else {
      console.log(`GitHub Actions will now automatically build and publish the v${version} portable package.`);
    }

  } catch (gitError) {
    console.error('Git integration failed. Make sure you are in a valid Git repository with correct push rights.');
    console.error(gitError);
    process.exit(1);
  }
}

release();
