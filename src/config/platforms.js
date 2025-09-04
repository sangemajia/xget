/**
 * Configuration object for different platform base URLs
 * @type {Object.<string, string>}
 */
export const PLATFORMS = {
  gh: 'https://github.com',
  gl: 'https://gitlab.com',
  gitea: 'https://gitea.com',
  codeberg: 'https://codeberg.org',
  sf: 'https://sourceforge.net',
  aosp: 'https://android.googlesource.com',
  hf: 'https://huggingface.co',
  civitai: 'https://civitai.com',
  npm: 'https://registry.npmjs.org',
  pypi: 'https://pypi.org',
  'pypi-files': 'https://files.pythonhosted.org',
  conda: 'https://repo.anaconda.com',
  'conda-community': 'https://conda.anaconda.org',
  maven: 'https://repo1.maven.org',
  apache: 'https://downloads.apache.org',
  gradle: 'https://plugins.gradle.org',
  homebrew: 'https://github.com/Homebrew',
  'homebrew-api': 'https://formulae.brew.sh/api',
  'homebrew-bottles': 'https://ghcr.io',
  rubygems: 'https://rubygems.org',
  cran: 'https://cran.r-project.org',
  cpan: 'https://www.cpan.org',
  ctan: 'https://tug.ctan.org',
  golang: 'https://proxy.golang.org',
  nuget: 'https://api.nuget.org',
  crates: 'https://crates.io',
  packagist: 'https://repo.packagist.org',
  debian: 'https://deb.debian.org',
  ubuntu: 'https://archive.ubuntu.com',
  fedora: 'https://dl.fedoraproject.org',
  rocky: 'https://download.rockylinux.org',
  opensuse: 'https://download.opensuse.org',
  arch: 'https://geo.mirror.pkgbuild.com',
  arxiv: 'https://arxiv.org',
  fdroid: 'https://f-droid.org',
  jenkins: 'https://updates.jenkins.io',

  // AI Inference Providers
  'ip-openai': 'https://api.openai.com',
  'ip-anthropic': 'https://api.anthropic.com',
  'ip-gemini': 'https://generativelanguage.googleapis.com',
  'ip-vertexai': 'https://aiplatform.googleapis.com',
  'ip-cohere': 'https://api.cohere.ai',
  'ip-mistralai': 'https://api.mistral.ai',
  'ip-xai': 'https://api.x.ai',
  'ip-githubmodels': 'https://models.github.ai',
  'ip-nvidiaapi': 'https://integrate.api.nvidia.com',
  'ip-perplexity': 'https://api.perplexity.ai',
  'ip-braintrust': 'https://api.braintrust.dev',
  'ip-groq': 'https://api.groq.com',
  'ip-cerebras': 'https://api.cerebras.ai',
  'ip-sambanova': 'https://api.sambanova.ai',
  'ip-huggingface': 'https://router.huggingface.co',
  'ip-together': 'https://api.together.xyz',
  'ip-replicate': 'https://api.replicate.com',
  'ip-fireworks': 'https://api.fireworks.ai',
  'ip-nebius': 'https://api.studio.nebius.ai',
  'ip-jina': 'https://api.jina.ai',
  'ip-voyageai': 'https://api.voyageai.com',
  'ip-falai': 'https://fal.run',
  'ip-novita': 'https://api.novita.ai',
  'ip-burncloud': 'https://ai.burncloud.com',
  'ip-openrouter': 'https://openrouter.ai',
  'ip-poe': 'https://api.poe.com',
  'ip-featherlessai': 'https://api.featherless.ai',
  'ip-hyperbolic': 'https://api.hyperbolic.xyz',

  // Container Registries
  'cr-quay': 'https://quay.io',
  'cr-gcr': 'https://gcr.io',
  'cr-mcr': 'https://mcr.microsoft.com',
  'cr-ecr': 'https://public.ecr.aws',
  'cr-ghcr': 'https://ghcr.io',
  'cr-gitlab': 'https://registry.gitlab.com',
  'cr-redhat': 'https://registry.redhat.io',
  'cr-oracle': 'https://container-registry.oracle.com',
  'cr-cloudsmith': 'https://docker.cloudsmith.io',
  'cr-digitalocean': 'https://registry.digitalocean.com',
  'cr-vmware': 'https://projects.registry.vmware.com',
  'cr-k8s': 'https://registry.k8s.io',
  'cr-heroku': 'https://registry.heroku.com',
  'cr-suse': 'https://registry.suse.com',
  'cr-opensuse': 'https://registry.opensuse.org',
  'cr-gitpod': 'https://registry.gitpod.io',
  'cr-docker': 'https://registry-1.docker.io'
};

/**
 * Escape special characters for regular expressions
 * @param {string} string - The string to escape
 * @returns {string} - The escaped string
 */
export function transformPath(path, platformKey) {
  // Input validation
  if (typeof path !== 'string' || path.trim() === '') {
    return '';
  }

  if (!PLATFORMS[platformKey]) {
    return path;
  }

  // Remove platform prefix
  const prefix = `/${platformKey.replace(/-/g, '/')}/`;
  const transformedPath = path.replace(new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`), '/');

  // Docker Hub specific handling
  if (platformKey === 'cr-docker') {
    if (transformedPath.startsWith('/v2/')) {
      const parts = transformedPath.split('/');
      
      // Official image detection (e.g. /v2/alpine)
      if (parts.length >= 3 && 
          !parts[2].includes('/') && 
          !parts[2].includes(':') && 
          !parts[2].includes('.')) {
        parts.splice(2, 0, 'library');
        return parts.join('/');
      }
      
      // Custom repository (e.g. /v2/dpanel/dpanel)
      return transformedPath;
    }
  }

  return transformedPath;
}

  // Special handling for crates.io API paths
  if (platformKey === 'crates') {
    if (transformedPath.startsWith('/')) {
      if (transformedPath === '/' || transformedPath.startsWith('/?')) {
        transformedPath = transformedPath.replace('/', '/api/v1/crates');
      } else {
        transformedPath = `/api/v1/crates${transformedPath}`;
      }
    }
  }

  // Special handling for Homebrew API paths
  if (platformKey === 'homebrew-api') {
    if (transformedPath.startsWith('/')) {
      return transformedPath;
    }
  }

  // Special handling for Homebrew bottles
  if (platformKey === 'homebrew-bottles') {
    if (transformedPath.startsWith('/')) {
      return transformedPath;
    }
  }

  // Special handling for Jenkins plugins
  if (platformKey === 'jenkins') {
    if (transformedPath.startsWith('/')) {
      if (transformedPath === '/update-center.json') {
        return '/current/update-center.json';
      } else if (transformedPath === '/update-center.actual.json') {
        return '/current/update-center.actual.json';
      } else if (
        transformedPath.startsWith('/experimental/') ||
        transformedPath.startsWith('/download/') ||
        transformedPath.startsWith('/current/')
      ) {
        return transformedPath;
      } else {
        return `/current${transformedPath}`;
      }
    }
  }

  // Special handling for Homebrew repositories
  if (platformKey === 'homebrew') {
    if (transformedPath.startsWith('/')) {
      return transformedPath;
    }
  }

  return transformedPath;
}