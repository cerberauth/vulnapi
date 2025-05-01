require 'open3'

def error(message, code = 1)
  # STDERR.puts(message)
  exit(code)
end

def usage
  "Usage: #{File.basename($PROGRAM_NAME)} [target min go version]"
end

def get_system_go_version
  go_path, status = Open3.capture2('which go')
  error('go: command not found') unless status.success?

  output, status = Open3.capture2('go version')
  error('Failed to retrieve Go version') unless status.success?

  pattern = /\bgo(\d+)\.(\d+)\.(\d+)\b/
  match = output.match(pattern)
  if match
    major, minor, patch = match.captures.map(&:to_i)
    return [major, minor, patch]
  end

  error("System Go version doesn't match the Go versioning system (goXX.YY.ZZ)!")
end

def parse_go_semver(entry)
  pattern = /^go(\d+)\.(\d+)\.(\d+)$/
  match = entry.match(pattern)
  if match
    major, minor, patch = match.captures.map(&:to_i)
    return [major, minor, patch]
  end

  error("\"#{entry}\" doesn't match the Go versioning system (goXX.YY.ZZ)!")
end

def main
  error(usage, 1) unless ARGV.size == 1

  min_version = parse_go_semver(ARGV[0])
  cur_version = get_system_go_version

  3.times do |i|
    if cur_version[i] < min_version[i]
      error("Installed Go version go#{cur_version.join('.')} is older than the minimum required version go#{min_version.join('.')}")
    end
  end

  0
end

exit(main)
