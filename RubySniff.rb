require 'pcaprub'
require 'optparse'
require 'ipaddr'
require 'colorize'
require 'terminal-table'
require 'tty-prompt'
require 'tty-spinner'

class WifiSniffer
  def initialize(interface, filter, output, verbose)
    @interface = interface
    @filter = filter
    @output = output
    @verbose = verbose
    @capture = Pcap::Capture.open_live(@interface, 65535, true, 0)
    @capture.setfilter(@filter) if @filter
    @rows = []
  end

  def start
    spinner = TTY::Spinner.new("[:spinner] Starting sniffer on interface #{@interface} with filter #{@filter}", format: :pulse_2)
    spinner.auto_spin
    File.open(@output, 'w') do |file|
      @capture.each_packet do |packet|
        parse_packet(packet, file)
      end
    end
    spinner.success("(done)")
    display_table
  end

  private

  def parse_packet(packet, file)
    eth_type = packet[12..13].unpack('H*').first
    return unless eth_type == '0800' # IPv4 packets

    src_mac = format_mac(packet[6..11])
    dst_mac = format_mac(packet[0..5])
    ip_header = packet[14..33]
    src_ip = IPAddr.new_ntoh(ip_header[12..15])
    dst_ip = IPAddr.new_ntoh(ip_header[16..19])
    protocol = ip_header[9].unpack('C').first
    total_length = ip_header[2..3].unpack('n').first

    protocol_name, src_port, dst_port = case protocol
                                        when 1
                                          ['ICMP', nil, nil]
                                        when 6
                                          tcp_header = packet[34..53]
                                          src_port = tcp_header[0..1].unpack('n').first
                                          dst_port = tcp_header[2..3].unpack('n').first
                                          ['TCP', src_port, dst_port]
                                        when 17
                                          udp_header = packet[34..41]
                                          src_port = udp_header[0..1].unpack('n').first
                                          dst_port = udp_header[2..3].unpack('n').first
                                          ['UDP', src_port, dst_port]
                                        else
                                          [protocol.to_s, nil, nil]
                                        end

    row = [src_mac, dst_mac, src_ip.to_s, dst_ip.to_s, protocol_name, src_port, dst_port, total_length]
    @rows << row
    output = row.map { |e| e.nil? ? '' : e.to_s }.join(" | ")
    puts output.colorize(:light_blue) if @verbose
    file.puts output
  end

  def format_mac(addr)
    addr.unpack('C*').map { |b| format('%02X', b) }.join(':')
  end

  def display_table
    table = Terminal::Table.new :headings => ['Source MAC', 'Destination MAC', 'Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'Length'], :rows => @rows
    puts table
  end
end

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: wifi_sniffer.rb [options]"

  opts.on("-i", "--interface INTERFACE", "Network interface to sniff") do |v|
    options[:interface] = v
  end

  opts.on("-f", "--filter FILTER", "BPF filter string") do |v|
    options[:filter] = v
  end

  opts.on("-o", "--output FILE", "Output file for captured packets") do |v|
    options[:output] = v
  end

  opts.on("-v", "--verbose", "Run in verbose mode") do |v|
    options[:verbose] = true
  end
end.parse!

if options[:interface].nil? || options[:output].nil?
  puts "Interface and output file are required."
  exit 1
end

begin
  sniffer = WifiSniffer.new(options[:interface], options[:filter], options[:output], options[:verbose])
  sniffer.start
rescue Interrupt
  puts "\nSniffer stopped by user."
rescue => e
  puts "Error: #{e.message}"
end
