require "vagrant"

module VagrantPlugins
  module CommunicatorSerial
    class Plugin < Vagrant.plugin("2")
      name "serial communicator"
      description <<-DESC
      This plugin allows Vagrant to communicate with remote machines using
      the first serial port as the underlying protocol.
      DESC

      communicator("serial") do
        require File.expand_path("../communicator", __FILE__)
        Communicator
      end
    end
  end
end
