/** Selected paths, with compatibility for scans created before multiple paths. */
export function selectedScanPaths(value: {
  code_scan_paths?: unknown;
  code_scan_path?: unknown;
  project_path?: unknown;
}): string[] {
  const paths = Array.isArray(value.code_scan_paths)
    ? value.code_scan_paths.filter((path): path is string => typeof path === "string").map((path) => path.trim()).filter(Boolean)
    : [];
  if (paths.length) return [...new Set(paths)];
  const fallback = [value.code_scan_path, value.project_path].find((path) => typeof path === "string" && path.trim());
  return typeof fallback === "string" ? [fallback.trim()] : [];
}
