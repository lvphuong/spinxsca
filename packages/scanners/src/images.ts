import images from './images.json' with { type: 'json' };

export interface PinnedImage {
  repository: string;
  tag: string;
  /** Multi-architecture index digest. */
  digest: string;
  toolVersion: string;
}

export type ScannerImage = 'semgrep' | 'osv-scanner' | 'gitleaks' | 'trivy';

export const PINNED_IMAGES: Record<ScannerImage, PinnedImage> = images;

/** "<repository>:<tag>@<digest>" so docker always resolves the pinned content. */
export function imageRef(image: PinnedImage): string {
  return `${image.repository}:${image.tag}@${image.digest}`;
}
