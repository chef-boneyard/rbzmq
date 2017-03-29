$:.unshift(File.dirname(__FILE__) + '/lib')
require 'rbzmq/version'

Gem::Specification.new do |s|
  s.name = 'rbzmq'
  s.version = ZMQ::VERSION
  s.has_rdoc = true
  # s.license
  s.description = 'This gem provides a Ruby API for the ZeroMQ messaging library.'
  s.summary = 'Ruby API for ZeroMQ'
  s.authors = ['Martin Sustrik', 'Brian Buchanan', 'Douglas Triggs', 'Tyler Ball']
  s.email = ['sustrik@250bpm.com', 'bwb@holo.org', 'doug@opscode.com', 'tball@chef.io']
  s.homepage = 'http://www.zeromq.org/bindings:ruby'

  s.required_ruby_version = ">= 2.1"

  s.add_development_dependency "rake", "~> 10.1"
  s.add_development_dependency "rake-compiler", "~> 1.0"
  s.add_development_dependency "pry", "~> 0.9"
  s.add_development_dependency "pry-byebug", "~> 3.4"
  s.add_development_dependency "pry-stack_explorer", "~> 0.4"

  s.extensions = 'ext/zmq/extconf.rb'
  s.files = %w{ README.rdoc } + Dir.glob( "{lib,spec,ext}/**/*", File::FNM_DOTMATCH ).reject { |f| File.directory?(f) }
end
