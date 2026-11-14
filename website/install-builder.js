const menuButton = document.querySelector('.menu');
const navigation = document.querySelector('#nav');

menuButton.addEventListener('click', () => {
  const open = menuButton.getAttribute('aria-expanded') === 'true';
  menuButton.setAttribute('aria-expanded', String(!open));
  navigation.classList.toggle('open', !open);
});

navigation.addEventListener('click', () => {
  menuButton.setAttribute('aria-expanded', 'false');
  navigation.classList.remove('open');
});

const installationTabs = [...document.querySelectorAll('[data-install-tab]')];
const installationPanels = [...document.querySelectorAll('.installation-panel')];

function activateInstallationTab(tab, focus = false) {
  installationTabs.forEach(button => {
    const active = button === tab;
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
  });
  installationPanels.forEach(panel => {
    panel.hidden = panel.id !== tab.dataset.installTab;
  });
  if (focus) tab.focus();
}

installationTabs.forEach((tab, index) => {
  tab.addEventListener('click', () => activateInstallationTab(tab));
  tab.addEventListener('keydown', event => {
    let nextIndex;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') nextIndex = (index + 1) % installationTabs.length;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') nextIndex = (index - 1 + installationTabs.length) % installationTabs.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = installationTabs.length - 1;
    if (nextIndex === undefined) return;
    event.preventDefault();
    activateInstallationTab(installationTabs[nextIndex], true);
  });
});

const volumeSelect = document.querySelector('#install-volume');
const sourceInputs = [...document.querySelectorAll('input[name="source-volume"]')];
const bucketInput = document.querySelector('#install-bucket');
const timezoneInput = document.querySelector('#install-timezone');
const portInput = document.querySelector('#install-port');
const rcloneInput = document.querySelector('#install-rclone');
const stackOutput = document.querySelector('#stack-output');
const runnerOutput = document.querySelector('#runner-command');
const managerAddress = document.querySelector('#manager-address');
const builderError = document.querySelector('#builder-error');
const deploymentInputs = [...document.querySelectorAll('input[name="deployment-tool"]')];
const deploymentInstructions = [...document.querySelectorAll('[data-deployment-instructions]')];
const deploymentToolName = document.querySelector('#deployment-tool-name');
const portainerRootPath = document.querySelector('#portainer-root-path');
const containerManagerRootPath = document.querySelector('#container-manager-root-path');
let rcloneWasEdited = false;

const quote = value => JSON.stringify(String(value).trim());

function selectedSources() {
  return sourceInputs.filter(input => input.checked).map(input => input.value);
}

function buildInstallation() {
  const installationVolume = volumeSelect.value;
  const sources = selectedSources();
  const root = `/${installationVolume}/docker/synology-glacier-backup-manager`;
  const bucket = bucketInput.value.trim() || 'my-archive-bucket';
  const timezone = timezoneInput.value.trim() || 'UTC';
  const port = Math.min(65535, Math.max(1024, Number(portInput.value) || 8787));
  const rclone = rcloneInput.value.trim() || `/${installationVolume}/@rclone/rclone.conf`;
  const browseRoots = sources.map(volume => `/${volume}`).join(':');
  const sourceMounts = sources.map(volume => `/${volume}=/sources/${volume}`).join(',');

  builderError.hidden = sources.length > 0;
  stackOutput.textContent = sources.length ? `services:
  glacier-backup-manager:
    build:
      context: https://github.com/impala84/synology-glacier-backup-manager.git#main
    pull_policy: build
    container_name: synology-glacier-backup-manager
    restart: unless-stopped
    user: "0:0"
    environment:
      TZ: ${quote(timezone)}
      GBM_BUCKET: ${quote(bucket)}
      GBM_REMOTE: "aws-archive"
      GBM_RCLONE_CONFIG: ${quote(rclone)}
      GBM_DATA_DIR: "/data"
      GBM_LOG_DIR: "/logs"
      GBM_PORT: "8787"
      GBM_BROWSE_ROOTS: ${quote(browseRoots)}
      GBM_SOURCE_MOUNTS: ${quote(sourceMounts)}
    volumes:
      - ${root}/data:/data:rw
      - ${root}/logs:/logs:rw
${sources.map(volume => `      - /${volume}:/sources/${volume}:ro`).join('\n')}
    ports:
      - "${port}:8787"
    read_only: true
    tmpfs:
      - /tmp:size=32m,mode=1777
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    pids_limit: 128
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"` : '# Select at least one source volume.';

  runnerOutput.textContent = `/usr/bin/python3 ${root}/data/runner/glacier-runner.py \\
  --data-dir ${root}/data \\
  --log-dir ${root}/logs`;
  managerAddress.textContent = `http://your-nas:${port}`;
  portainerRootPath.textContent = root;
  containerManagerRootPath.textContent = root;
}

volumeSelect.addEventListener('change', () => {
  if (!rcloneWasEdited) rcloneInput.value = `/${volumeSelect.value}/@rclone/rclone.conf`;
  buildInstallation();
});

rcloneInput.addEventListener('input', () => { rcloneWasEdited = true; buildInstallation(); });
[...sourceInputs, bucketInput, timezoneInput, portInput].forEach(input => input.addEventListener('input', buildInstallation));

function selectDeploymentTool(tool) {
  deploymentInstructions.forEach(instructions => {
    instructions.hidden = instructions.dataset.deploymentInstructions !== tool;
  });
  deploymentToolName.textContent = tool === 'container-manager' ? 'Container Manager' : 'Portainer';
}

deploymentInputs.forEach(input => input.addEventListener('change', () => {
  if (input.checked) selectDeploymentTool(input.value);
}));

document.querySelectorAll('[data-copy-target]').forEach(button => button.addEventListener('click', async () => {
  const text = document.getElementById(button.dataset.copyTarget)?.textContent;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    const label = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = label; }, 1600);
  } catch {
    button.textContent = 'Select and copy';
  }
}));

document.querySelectorAll('[data-download-target]').forEach(button => button.addEventListener('click', () => {
  const text = document.getElementById(button.dataset.downloadTarget)?.textContent;
  if (!text || text.startsWith('# Select')) return;
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([`${text}\n`], { type: 'text/yaml' }));
  link.download = button.dataset.downloadName || 'compose.yaml';
  link.click();
  URL.revokeObjectURL(link.href);
}));

buildInstallation();
selectDeploymentTool(deploymentInputs.find(input => input.checked)?.value || 'portainer');
