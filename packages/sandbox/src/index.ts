export { ConfinementError, globToRegExp, RepositoryConfinement } from './confinement';
export { containerUser, type DockerSandboxOptions, DockerSandboxRunner } from './docker-runner';
export { type MaterializedCopy, type MaterializeOptions, materializeRedactedCopy } from './materialize';
export { isPinnedImage, PINNED_IMAGE, PROFILES, type ProfileSpec } from './profiles';
export { type AnalysisShellOptions, DEFAULT_TOOLBOX_IMAGE, runAnalysisShell } from './shell';
export { NODE_IMAGE, PYTHON_IMAGE, runProjectTests, type TestRunOutcome } from './test-runner';
export { localValidationPort, oracleGuide, type ValidationPortOptions } from './validation';
