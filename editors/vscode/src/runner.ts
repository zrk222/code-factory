export function factoryExecutable(command: string, platform = process.platform): string {
  return platform === "win32" && command === "factory" ? "factory.exe" : command;
}

export function isFeatureName(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(value);
}
