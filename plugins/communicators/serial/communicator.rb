require 'logger'
require 'pathname'
require 'stringio'
require 'thread'
require 'timeout'

require 'log4r'
require 'serial'

require 'vagrant/util/ansi_escape_code_remover'
require 'vagrant/util/file_mode'
require 'vagrant/util/keypair'
require 'vagrant/util/platform'
require 'vagrant/util/retryable'

module VagrantPlugins
  module CommunicatorSerial
    # This class provides communication with the VM via serial port.
    class Communicator < Vagrant.plugin("2", :communicator)
      include Vagrant::Util::ANSIEscapeCodeRemover
      include Vagrant::Util::Retryable

      def self.match?(machine)
        # All machines are currently expected to have serial port.
        true
      end

      def initialize(machine)
        @lock    = Mutex.new
        @machine = machine
        @logger  = Log4r::Logger.new("vagrant::communication::serial")
        @connection = nil
      end

      def wait_for_ready(timeout)
        Timeout.timeout(timeout) do
          # Wait for serial_info to be ready
          serial_info = nil
          while true
            serial_info = @machine.serial_info
            break if serial_info
            sleep 0.5
          end

          # Got it! Let the user know what we're connecting to.
          @machine.ui.detail("Serial address: #{serial_info[:host]}:#{serial_info[:port]}")
          @machine.ui.detail("Serial username: #{serial_info[:username]}")

          last_message = nil
          last_message_repeat_at = 0
          while true
            message  = nil
            begin
              begin
                connect(retries: 1)
                return true if ready?
              rescue Vagrant::Errors::VagrantError => e
                @logger.info("Serial not ready: #{e.inspect}")
                raise
              end
            rescue Vagrant::Errors::SerialConnectionTimeout
              message = "Connection timeout."
            rescue Vagrant::Errors::SerialDisconnected
              message = "Remote connection disconnect."
            rescue Vagrant::Errors::SerialConnectionReset
              message = "Connection reset."
            rescue Vagrant::Errors::SerialHostDown
              message = "Host appears down."
            rescue Vagrant::Errors::SerialNoRoute
              message = "Host unreachable."
            rescue Vagrant::Errors::SerialInvalidShell
              raise
            rescue Vagrant::Errors::VagrantError => e
              # Ignore it, Serial is not ready, some other error.
            end

            # If we have a message to show, then show it. We don't show
            # repeated messages unless they've been repeating longer than
            # 10 seconds.
            if message
              message_at   = Time.now.to_f
              show_message = true
              if last_message == message
                show_message = (message_at - last_message_repeat_at) > 10.0
              end

              if show_message
                @machine.ui.detail("Warning: #{message} Retrying...")
                last_message = message
                last_message_repeat_at = message_at
              end
            end
          end
        end
      rescue Timeout::Error
        return false
      end

      def ready?
        @logger.debug("Checking whether Serial is ready...")

        # Attempt to connect. This will raise an exception if it fails.
        begin
          connect
          @logger.info("Serial is ready!")
        rescue Vagrant::Errors::VagrantError => e
          # We catch a `VagrantError` which would signal that something went
          # wrong expectedly in the `connect`, which means we didn't connect.
          @logger.info("Serial not up: #{e.inspect}")
          return false
        end

        # If we used a password, then insert the insecure key
        serial_info = @machine.serial_info

        # If we reached this point then we successfully connected
        true
      end

      def execute(command, opts=nil, &block)
        opts = {
          error_check: true,
          error_class: Vagrant::Errors::VagrantError,
          error_key:   :serial_bad_exit_status,
          good_exit:   0,
          command:     command,
          shell:       nil,
          sudo:        false,
        }.merge(opts || {})

        opts[:good_exit] = Array(opts[:good_exit])

        # Connect via Serial and execute the command in the shell.
        stdout = ""
        stderr = ""
        exit_status = connect do |connection|
          shell_opts = {
            sudo: opts[:sudo],
            shell: opts[:shell],
          }

          shell_execute(connection, command, **shell_opts) do |type, data|
            if type == :stdout
              stdout += data
            elsif type == :stderr
              stderr += data
            end

            block.call(type, data) if block
          end
        end

        # Check for any errors
        if opts[:error_check] && !opts[:good_exit].include?(exit_status)
          # The error classes expect the translation key to be _key,
          # but that makes for an ugly configuration parameter, so we
          # set it here from `error_key`
          error_opts = opts.merge(
            _key: opts[:error_key],
            stdout: stdout,
            stderr: stderr
          )
          raise opts[:error_class], error_opts
        end

        # Return the exit status
        exit_status
      end

      def sudo(command, opts=nil, &block)
        # Run `execute` but with the `sudo` option.
        opts = { sudo: true }.merge(opts || {})
        execute(command, opts, &block)
      end

      def download(from, to=nil)
        @logger.debug("Downloading: #{from} to #{to}")

	# TODO: implement
	@logger.error("Not implemented!")
	raise Vagrant::Error::NotImplemented
      end

      def test(command, opts=nil)
        opts = { error_check: false }.merge(opts || {})
        execute(command, opts) == 0
      end

      def upload(from, to)
        @logger.debug("Uploading: #{from} to #{to}")

	# TODO: implement
	@logger error("Not implemented!")
	raise Vagrant::Error::NotImplemented
      rescue RuntimeError => e
        # Net::SCP raises a runtime error for this so the only way we have
        # to really catch this exception is to check the message to see if
        # it is something we care about. If it isn't, we re-raise.
        raise if e.message !~ /Permission denied/

        # Otherwise, it is a permission denied, so let's raise a proper
        # exception
        raise Vagrant::Errors::SCPPermissionDenied,
          from: from.to_s,
          to: to.to_s
      end

      protected

      # Opens an Serial connection and yields it to a block.
      def connect(**opts)
        if @connection && !@connection.closed?
          # There is a chance that the socket is closed despite us checking
          # 'closed?' above. To test this we need to send data through the
          # socket.
          #
          # We wrap the check itself in a 5 second timeout because there
          # are some cases where this will just hang.
          begin
            Timeout.timeout(5) do
              @connection.exec!("")
            end
          rescue Exception => e
            @logger.info("Connection errored, not re-using. Will reconnect.")
            @logger.debug(e.inspect)
            @connection = nil
          end

          # If the @connection is still around, then it is valid,
          # and we use it.
          if @connection
            @logger.debug("Re-using Serial connection.")
            return yield @connection if block_given?
            return
          end
        end

        # Get the Serial info for the machine, raise an exception if the
        # provider is saying that Serial is not ready.
        serial_info = @machine.serial_info
        raise Vagrant::Errors::SerialNotReady if serial_info.nil?

        # Default some options
        opts[:retries] = 5 if !opts.key?(:retries)

        # Build the options we'll use to initiate the connection via Net::Serial
        common_connect_opts = {
          config:                false,
          send_env:              serial_info[:forward_env],
          password:              serial_info[:password],
          port:                  serial_info[:port],
          timeout:               15,
          verbose:               :debug,
        }

        # Connect to Serial, giving it a few tries
        connection = nil
        begin
          # These are the exceptions that we retry because they represent
          # errors that are generally fixed from a retry and don't
          # necessarily represent immediate failure cases.
          exceptions = [
            Errno::EACCES,
            Errno::EADDRINUSE,
            Errno::ECONNREFUSED,
            Errno::ECONNRESET,
            Errno::ENETUNREACH,
            Errno::EHOSTUNREACH,
            Net::Serial::Disconnect,
            Timeout::Error
          ]

          timeout = 60

          @logger.info("Attempting Serial connection...")
          connection = retryable(tries: opts[:retries], on: exceptions) do
            Timeout.timeout(timeout) do
              begin
                # This logger will get the Net-Serial log data for us.
                serial_logger_io = StringIO.new
                serial_logger    = Logger.new(serial_logger_io)

                # Setup logging for connections
                connect_opts = common_connect_opts.dup
                connect_opts[:logger] = serial_logger

                @logger.info("Attempting to connect to Serial...")
                @logger.info("  - Host: #{serial_info[:host]}")
                @logger.info("  - Port: #{serial_info[:port]}")
                @logger.info("  - Username: #{serial_info[:username]}")
                @logger.info("  - Password? #{!!serial_info[:password]}")
                @logger.debug("  - connect_opts: #{connect_opts}")

                Net::Serial.start(serial_info[:host], serial_info[:username], connect_opts)
              ensure
                # Make sure we output the connection log
                @logger.debug("== Net-Serial connection debug-level log START ==")
                @logger.debug(serial_logger_io.string)
                @logger.debug("== Net-Serial connection debug-level log END ==")
              end
            end
          end
        rescue Errno::EACCES
          # This happens on connect() for unknown reasons yet...
          raise Vagrant::Errors::SerialConnectEACCES
        rescue Errno::ETIMEDOUT, Timeout::Error
          # This happens if we continued to timeout when attempting to connect.
          raise Vagrant::Errors::SerialConnectionTimeout
        rescue Net::Serial::AuthenticationFailed
          # This happens if authentication failed. We wrap the error in our
          # own exception.
          raise Vagrant::Errors::SerialAuthenticationFailed
        rescue Net::Serial::Disconnect
          # This happens if the remote server unexpectedly closes the
          # connection. This is usually raised when Serial is running on the
          # other side but can't properly setup a connection. This is
          # usually a server-side issue.
          raise Vagrant::Errors::SerialDisconnected
        rescue Errno::ECONNREFUSED
          # This is raised if we failed to connect the max amount of times
          raise Vagrant::Errors::SerialConnectionRefused
        rescue Errno::ECONNRESET
          # This is raised if we failed to connect the max number of times
          # due to an ECONNRESET.
          raise Vagrant::Errors::SerialConnectionReset
        rescue Errno::EHOSTDOWN
          # This is raised if we get an ICMP DestinationUnknown error.
          raise Vagrant::Errors::SerialHostDown
        rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH
          # This is raised if we can't work out how to route traffic.
          raise Vagrant::Errors::SerialNoRoute
        rescue Net::Serial::Exception => e
          # This is an internal error in Net::Serial
          raise Vagrant::Errors::NetSerialException, message: e.message
        rescue NotImplementedError
          # This is raised if a private key type that Net-Serial doesn't support
          # is used. Show a nicer error.
          raise Vagrant::Errors::SerialKeyTypeNotSupported
        end

        @connection          = connection
        @connection_serial_info = serial_info

        # Yield the connection that is ready to be used and
        # return the value of the block
        return yield connection if block_given?
      end

      # The shell wrapper command used in shell_execute defined by
      # the sudo and shell options.
      def shell_cmd(opts)
        sudo  = opts[:sudo]
        shell = opts[:shell]

        # Determine the shell to execute. Prefer the explicitly passed in shell
        # over the default configured shell. If we are using `sudo` then we
        # need to wrap the shell in a `sudo` call.
        cmd = @machine.config.serial.shell
        cmd = shell if shell
        cmd = @machine.config.serial.sudo_command.gsub("%c", cmd) if sudo
        cmd
      end

      # Executes the command on an Serial connection within a login shell.
      def shell_execute(connection, command, **opts)
        opts = {
          sudo: false,
          shell: nil
        }.merge(opts)

        sudo  = opts[:sudo]

        @logger.info("Execute: #{command} (sudo=#{sudo.inspect})")
        exit_status = nil

        # These variables are used to scrub PTY output if we're in a PTY
        pty = false
        pty_stdout = ""

        # Open the channel so we can execute or command
        channel = connection.open_channel do |ch|
          if @machine.config.serial.pty
            ch.request_pty do |ch2, success|
              pty = success && command != ""

              if success
                @logger.debug("pty obtained for connection")
              else
                @logger.warn("failed to obtain pty, will try to continue anyways")
              end
            end
          end

          marker_found = false
          data_buffer = ''
          stderr_marker_found = false
          stderr_data_buffer = ''

          ch.exec(shell_cmd(opts)) do |ch2, _|
            # Setup the channel callbacks so we can get data and exit status
            ch2.on_data do |ch3, data|
              # Filter out the clear screen command
              data = remove_ansi_escape_codes(data)

              if pty
                pty_stdout << data
              else
                if !marker_found
                  data_buffer << data
                  marker_index = data_buffer.index(CMD_GARBAGE_MARKER)
                  if marker_index
                    marker_found = true
                    data_buffer.slice!(0, marker_index + CMD_GARBAGE_MARKER.size)
                    data.replace(data_buffer)
                    data_buffer = nil
                  end
                end

                if block_given? && marker_found
                  yield :stdout, data
                end
              end
            end

            ch2.on_extended_data do |ch3, type, data|
              # Filter out the clear screen command
              data = remove_ansi_escape_codes(data)
              @logger.debug("stderr: #{data}")
              if !stderr_marker_found
                stderr_data_buffer << data
                marker_index = stderr_data_buffer.index(CMD_GARBAGE_MARKER)
                if marker_index
                  marker_found = true
                  stderr_data_buffer.slice!(0, marker_index + CMD_GARBAGE_MARKER.size)
                  data.replace(stderr_data_buffer)
                  data_buffer = nil
                end
              end

              if block_given? && marker_found
                yield :stderr, data
              end
            end

            ch2.on_request("exit-status") do |ch3, data|
              exit_status = data.read_long
              @logger.debug("Exit status: #{exit_status}")

              # Close the channel, since after the exit status we're
              # probably done. This fixes up issues with hanging.
              ch.close
            end

            # Set the terminal
            ch2.send_data generate_environment_export("TERM", "vt100")

            # Set Serial_AUTH_SOCK if we are in sudo and forwarding agent.
            # This is to work around often misconfigured boxes where
            # the Serial_AUTH_SOCK env var is not preserved.
            if @connection_serial_info[:forward_agent] && sudo
              auth_socket = ""
              execute("echo; printf $Serial_AUTH_SOCK") do |type, data|
                if type == :stdout
                  auth_socket += data
                end
              end

              if auth_socket != ""
                # Make sure we only read the last line which should be
                # the $Serial_AUTH_SOCK env var we printed.
                auth_socket = auth_socket.split("\n").last.chomp
              end

              if auth_socket == ""
                @logger.warn("No Serial_AUTH_SOCK found despite forward_agent being set.")
              else
                @logger.info("Setting Serial_AUTH_SOCK remotely: #{auth_socket}")
                ch2.send_data generate_environment_export("Serial_AUTH_SOCK", auth_socket)
              end
            end

            # Output the command. If we're using a pty we have to do
            # a little dance to make sure we get all the output properly
            # without the cruft added from pty mode.
            if pty
              data = "stty raw -echo\n"
              data += generate_environment_export("PS1", "")
              data += generate_environment_export("PS2", "")
              data += generate_environment_export("PROMPT_COMMAND", "")
              data += "printf #{PTY_DELIM_START}\n"
              data += "#{command}\n"
              data += "exitcode=$?\n"
              data += "printf #{PTY_DELIM_END}\n"
              data += "exit $exitcode\n"
              data = data.force_encoding('ASCII-8BIT')
              ch2.send_data data
            else
              ch2.send_data "printf '#{CMD_GARBAGE_MARKER}'\n(>&2 printf '#{CMD_GARBAGE_MARKER}')\n#{command}\n".force_encoding('ASCII-8BIT')
              # Remember to exit or this channel will hang open
              ch2.send_data "exit\n"
            end

            # Send eof to let server know we're done
            ch2.eof!
          end
        end

        begin
          keep_alive = nil

          if @machine.config.serial.keep_alive
            # Begin sending keep-alive packets while we wait for the script
            # to complete. This avoids connections closing on long-running
            # scripts.
            keep_alive = Thread.new do
              loop do
                sleep 5
                @logger.debug("Sending Serial keep-alive...")
                connection.send_global_request("keep-alive@openssh.com")
              end
            end
          end

          # Wait for the channel to complete
          begin
            channel.wait
          rescue Errno::ECONNRESET, IOError
            @logger.info(
              "Serial connection unexpected closed. Assuming reboot or something.")
            exit_status = 0
            pty = false
          rescue Net::Serial::ChannelOpenFailed
            raise Vagrant::Errors::SerialChannelOpenFail
          rescue Net::Serial::Disconnect
            raise Vagrant::Errors::SerialDisconnected
          end
        ensure
          # Kill the keep-alive thread
          keep_alive.kill if keep_alive
        end

        # If we're in a PTY, we now finally parse the output
        if pty
          @logger.debug("PTY stdout: #{pty_stdout}")
          if !pty_stdout.include?(PTY_DELIM_START) || !pty_stdout.include?(PTY_DELIM_END)
            @logger.error("PTY stdout doesn't include delims")
            raise Vagrant::Errors::SerialInvalidShell.new
          end

          data = pty_stdout[/.*#{PTY_DELIM_START}(.*?)#{PTY_DELIM_END}/m, 1]
          data ||= ""
          @logger.debug("PTY stdout parsed: #{data}")
          yield :stdout, data if block_given?
        end

        # Return the final exit status
        return exit_status
      end

      # Opens an SCP connection and yields it so that you can download
      # and upload files.
      def scp_connect
        # Connect to SCP and yield the SCP object
        connect do |connection|
          scp = Net::SCP.new(connection)
          return yield scp
        end
      rescue Net::SCP::Error => e
        # If we get the exit code of 127, then this means SCP is unavailable.
        raise Vagrant::Errors::SCPUnavailable if e.message =~ /\(127\)/

        # Otherwise, just raise the error up
        raise
      end

      # This will test whether path is the Vagrant insecure private key.
      #
      # @param [String] path
      def insecure_key?(path)
        return false if !path
        return false if !File.file?(path)
        source_path = Vagrant.source_root.join("keys", "vagrant")
        return File.read(path).chomp == source_path.read.chomp
      end

      def generate_environment_export(env_key, env_value)
        template = @machine.config.serial.export_command_template
        template.sub("%ENV_KEY%", env_key).sub("%ENV_VALUE%", env_value) + "\n"
      end
    end
  end
end
