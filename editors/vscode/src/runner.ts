export function factoryExecutable(command: string, platform = process.platform): string {
  return platform === "win32" && command === "factory" ? "factory.exe" : command;
}

export function isFeatureName(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(value);
}

export function factoryStudioUrl(output: string): string | undefined {
  const match = output.match(/Factory Studio:\s+(http:\/\/127\.0\.0\.1:\d+\/)/);
  return match?.[1];
}
