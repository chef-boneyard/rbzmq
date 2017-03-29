$LOAD_PATH << File.expand_path(File.join(File.dirname( __FILE__ ), "lib"))

require 'rubygems/package_task'
require 'rake/extensiontask'

gemspec = eval(IO.read(File.expand_path("../rbzmq.gemspec", __FILE__)))
Gem::PackageTask.new(gemspec).define

task :clean do
  sh "rm -f Gemfile.lock"
  sh "rm -rf pkg/* tmp/* .bundle lib/rbzmq/ext/*"
end

spec = Gem::Specification.load('rbzmq.gemspec')

Rake::ExtensionTask.new do |ext|
  ext.name = 'zmq'
  ext.lib_dir = 'lib/rbzmq/ext'
  ext.ext_dir = 'ext/zmq'
  ext.gem_spec = spec
end
