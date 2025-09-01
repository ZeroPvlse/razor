// this just contains random parts of the code so "main functionality"
// isn't full of bullshit
package mess

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func GenerateTemplate(filename string) error {
	if strings.Contains(filename, ".") {
		return errors.New("template file name have contain '.yaml' suffix")
	}

	fileSuff := fmt.Sprintf("%s.yaml", filename)

	file, err := os.Create(fileSuff)
	if err != nil {
		return errors.New("template file name have contain '.yaml' suffix")
	}
	defer file.Close()

	fmt.Printf("Generated: %s successfuly!\n", fileSuff)
	file.WriteString(`# RAZOR engagement config FILL THIS B4 YOU GO!!
name: ""                            # what are we calling this job? keep it short. shows up in reports/artifacts.
client: ""                          # who hired us. spell it right so we don't look like amateurs.

scope:
  targets: []                       # EXACT stuff we're allowed to poke: domains/IPs/CIDRs. if it’s not here, we don’t touch it.
  include_ports: []                 # only list ports if the client is picky. blank = safe defaults; we won't scan half the internet.
  max_hosts: 0                      # seatbelt for huge scopes. 0 = no cap. turn it up if time is tight and scope is thicc. it basically means from whole scope how many findings are the "key ones". it will automatically pick the most crucial ones UP TO max_hosts value.
  allow_intrusive: false            # leave false unless client said "go harder." true = spicier checks, more noise, more sideeye. (XSSscannig, sqli shit like that)
  time_window:                      # optional 'do it off-hours' window (UTC). leave blank if nobody cares.
    start: ""                       # e.g. "2025-09-01T19:00:00Z" - or empty if no window.
    end: ""                         # e.g. "2025-09-02T06:00:00Z" - or empty, same deal.

limits:
  rps_per_host: 2                   # requests/sec per host. chill setting so WAFs don't start drama.
  total_requests_per_host: 1000     # hard stop so a typo doesn't firehose a site. we’re scanners, not DDoSers.
  concurrency: 10                   # how many things we juggle at once. higher = faster & louder. lower = slower & stealthier.
  connect_timeout_s: 5              # if we can't connect by now, we move on. life's short.
  request_timeout_s: 10             # don't wait forever for sleepy servers.
  retries: 2                        # how many second chances we give flaky endpoints before we say "nah."

report:
  deliverables: []                  # what to spit out. pick from: pdf_exec, html_tech, json_findings. blank = reasonable defaults.
  redactions: true                  # keep secrets blurred in evidence/logs. leave true unless you enjoy awkward calls.
  cvss: "v3.1"                      # severity flavor. you probably don't need to touch this.
  include_screenshots: true         # screenshots = receipts. turn off only if storage is crying.
  out_dir: ""                       # where to dump files. blank = default folder; we keep it tidy.

notes:
  stack_hints: []                   # client hints like "WordPress", "Nginx", "AWS". guesses welcome; helps aim checks.
  contacts: []                      # who we ping if something looks spicy. emails or chat handles. no ghosting.
  tags: []                          # labels for later: "prod", "EU", "quarterly", "pls-don't-break".`)

	return nil
}

const GenLogo string = `
░█████████     ░███    ░█████████   ░██████   ░█████████            ░██████  ░██████████ ░███    ░██ 
░██     ░██   ░██░██         ░██   ░██   ░██  ░██     ░██          ░██   ░██ ░██         ░████   ░██ 
░██     ░██  ░██  ░██       ░██   ░██     ░██ ░██     ░██         ░██        ░██         ░██░██  ░██ 
░█████████  ░█████████    ░███    ░██     ░██ ░█████████  ░██████ ░██  █████ ░█████████  ░██ ░██ ░██ 
░██   ░██   ░██    ░██   ░██      ░██     ░██ ░██   ░██           ░██     ██ ░██         ░██  ░██░██ 
░██    ░██  ░██    ░██  ░██        ░██   ░██  ░██    ░██           ░██  ░███ ░██         ░██   ░████ 
░██     ░██ ░██    ░██ ░█████████   ░██████   ░██     ░██           ░█████░█ ░██████████ ░██    ░███ 
									
										by ZeroPvlse
	`

const MainLogo string = `

	░██░████  ░██████   ░█████████  ░███████  ░██░████ 
	░███           ░██       ░███  ░██    ░██ ░███     
	░██       ░███████     ░███    ░██    ░██ ░██      
	░██      ░██   ░██   ░███      ░██    ░██ ░██      
	░██       ░█████░██ ░█████████  ░███████  ░██      
                                                   
				                 by ZeroPvlse
`

func PrintAscii(logo string) {
	fmt.Println(logo)

}
