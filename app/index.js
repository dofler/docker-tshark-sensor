xconst spawn = require('child_process').spawn
const request = require('request')
const chalk = require('chalk')

const parserName = 'Tshark'

// The child process.  If ngrep terminates, we will attempt to restart it,
// and would prefer to keep the child itself out of the recursion.
var child

function run() {
  var skip = true;    // The line skipping flag. Set to true until we encounter a packet.
  var raw_packet = '';  // The raw packet string. XML assembly happens on this variable.
  console.log(`${parserName}(${chalk.blue('startup')}) : Monitoring on ${process.env.MONITOR_INTERFACE}`)
  console.log(`${parserName}(${chalk.blue('startup')}) : Starting up child process`)
  child = spawn('dumpcap', [
      '-i', process.env.MONITOR_INTERFACE,
      '-P', '-w', '-', '|'
      'tshark', '-T', 'psml', '-PS', '-l', '-r', '-'
  ], {shell: '/bin/sh'})

  // If we have been requested to shut down, then we should do so gracefully
  process.on('SIGUSR2', function(){
    console.log(`${parserName}(${chalk.blue('shutdown')}) : Shutting down child process`)
    child.stdin.pause()
    child.kill()
    process.exit()
  })

  // Pass anything from standard error directly to the log.
  child.stderr.on('data', function(data) {
    console.log(`${parserName}(${chalk.yellow('stderr')}) : ${data.toString().replace(/(\r\n|\n|\r)/gm)}`)
  })

  // If ngrep exits for some reason, we should log the event to the console
  // and then initiate a new instance to work from.
  child.on('close', function(code) {
    console.log(`${parserName}(${chalk.yellow('close')}) : Child terminated with code ${code}`)
    run()
  })

  // If ngrep is failing to start, then we need to log that event
  child.on('error', function(error) {
    console.log(`${parserName}(${chalk.red('close')}) : Could not start the child process`)
  })

  // When ngrep outputs data to standard output, we want to capture that
  // data, interpret it, and hand it off to the database.
  child.stdout.on('data', function(data) {
    // As Tshark is generating enough output to cause Node.js to buffer
    // the output, we want to make sure that we are parsing through the
    // line-by-line and reconstructing complete packet definitions.  So
    // we will split the output buffer based on carriage returns and
    // interact with each line.
    var lines = data.toString().split('\n');
    for (var i in lines) {

      // The first several lines output from TShark include the XML
      // definition and the schema for the PSML specification.  As
      // these lines are not important to use, we will want to simply
      // ignore them.  I'm using a rudimentary skip flag that is set
      // to true until we see a <packet> flag in the stream.
      if (skip) {
        if (lines[i].indexOf('<packet>') > -1){
          skip = false;
          console.log('TShark: Starting to process packet data.')
        }
      }
      if (!(skip)) {
        raw_packet = raw_packet.concat(lines[i])

        // New we need to see if the raw_packet is complete.  If it is, then
        // we will need to parse the raw_packet and attempt to marry it to
        // the data we have on hand.
        if (lines[i].indexOf('</packet>') > -1) {
          var pkt = raw_packet;
          raw_packet = ''
          parseXML(pkt, function(err, packet) {
            // The PSML specification is as such:
            //
            //  <structure>
            //    <section>N.</section> 
            //    <section>Time</section> 
            //    <section>Link Layer</section> 
            //    <section>Network</section> 
            //    <section>Transport</section> 
            //    <section>Application</section>
            //    <section>(OPTIONAL) Other Information</section>
            //  </structure>
            // 
            // What we are looking for is the transport protocol, which
            // is the 5th section in the PSML spec.  We will take that
            // peice of information and then keep track fo the number of
            // packets we see with that transport.
            var transport = packet.packet.section[4];
            if (!(transport in transports)) {
              transports[transport] = 0;
            }
            transports[transport] += 1;
            //console.log('TShark: ' + transport + '++')
          });
        }
      }
    }   
  })
}