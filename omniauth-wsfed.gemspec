# -*- encoding: utf-8 -*-
require File.expand_path('../lib/omniauth-wsfed/version', __FILE__)

Gem::Specification.new do |gem|

  gem.name          = 'omniauth-wsfed'
  gem.version       = OmniAuth::WSFed::VERSION
  gem.summary       = %q{A WS-Federation + WS-Trust strategy for OmniAuth.}
  gem.description   = %q{OmniAuth WS-Federation strategy enabling integration with Windows Azure Access Control Service (ACS), Active Directory Federation Services (ADFS) 2.0, custom Identity Providers built with Windows Identity Foundation (WIF) or any other Identity Provider supporting the WS-Federation protocol.}

  gem.authors       = ['Keith Beckman']
  gem.email         = ['kbeckman.c4sc@gmail.com']
  gem.homepage      = 'https://github.com/kbeckman/omniauth-wsfed'
  gem.license       = 'MIT'

  gem.add_runtime_dependency 'omniauth',          '~> 2.0'
  gem.add_runtime_dependency 'nokogiri',          '>= 1.10.5'
  gem.add_runtime_dependency 'rexml'

  gem.add_development_dependency 'rspec',     '~> 3.13',  '>= 3.0.0'
  gem.add_development_dependency 'rake',      '~> 10.1',  '>= 10.1.0'
  gem.add_development_dependency 'rack-test', '~> 0.6',   '>= 0.6.2'

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']

end
