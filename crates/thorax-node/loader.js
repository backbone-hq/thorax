function linuxLibc(report) {
  // Node reports glibc at runtime. Its absence on Linux means a musl build.
  return report && report.getReport().header.glibcVersionRuntime ? 'gnu' : 'musl'
}

function bindingName(platform, arch, report = process.report) {
  if (platform === 'linux' && (arch === 'x64' || arch === 'arm64')) {
    return `thorax.linux-${arch}-${linuxLibc(report)}.node`
  }
  if (platform === 'darwin' && (arch === 'x64' || arch === 'arm64')) {
    return `thorax.darwin-${arch}.node`
  }
  if (platform === 'win32' && (arch === 'x64' || arch === 'arm64')) {
    return `thorax.win32-${arch}-msvc.node`
  }
  throw new Error(`Unsupported Thorax platform: ${platform}-${arch}`)
}

module.exports = { bindingName }
