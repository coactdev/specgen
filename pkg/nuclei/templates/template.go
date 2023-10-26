//go:generate dstdocgen -path "" -structure Template -output templates_doc.go -package templates
package templates

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	validate "github.com/go-playground/validator/v10"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/code"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/file"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/javascript"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/ssl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/websocket"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/whois"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v2"
)

// Template is a YAML input file which defines all the requests and
// other metadata for a template.
type Template struct {
	// description: |
	//   ID is the unique id for the template.
	//
	//   #### Good IDs
	//
	//   A good ID uniquely identifies what the requests in the template
	//   are doing. Let's say you have a template that identifies a git-config
	//   file on the webservers, a good name would be `git-config-exposure`. Another
	//   example name is `azure-apps-nxdomain-takeover`.
	// examples:
	//   - name: ID Example
	//     value: "\"CVE-2021-19520\""
	ID string `yaml:"id" json:"id" jsonschema:"title=id of the template,description=The Unique ID for the template,example=cve-2021-19520,pattern=^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"`
	// description: |
	//   Info contains metadata information about the template.
	// examples:
	//   - value: exampleInfoStructure
	Info model.Info `yaml:"info" json:"info" jsonschema:"title=info for the template,description=Info contains metadata for the template"`
	// description: |
	//   Flow contains the execution flow for the template.
	// examples:
	//   - flow: |
	// 		for region in regions {
	//		    http(0)
	//		 }
	//		 for vpc in vpcs {
	//		    http(1)
	//		 }
	//
	Flow string `yaml:"flow,omitempty" json:"flow,omitempty" jsonschema:"title=template execution flow in js,description=Flow contains js code which defines how the template should be executed"`
	// description: |
	//   Requests contains the http request to make in the template.
	//   WARNING: 'requests' will be deprecated and will be removed in a future release. Please use 'http' instead.
	// examples:
	//   - value: exampleNormalHTTPRequest
	RequestsHTTP []*http.Request `yaml:"requests,omitempty" json:"requests,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template"`
	// description: |
	//   HTTP contains the http request to make in the template.
	// examples:
	//   - value: exampleNormalHTTPRequest
	// RequestsWithHTTP is placeholder(internal) only, and should not be used instead use RequestsHTTP
	// Deprecated: Use RequestsHTTP instead.
	RequestsWithHTTP []*http.Request `yaml:"http,omitempty" json:"http,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template"`
	// description: |
	//   DNS contains the dns request to make in the template
	// examples:
	//   - value: exampleNormalDNSRequest
	RequestsDNS []*dns.Request `yaml:"dns,omitempty" json:"dns,omitempty" jsonschema:"title=dns requests to make,description=DNS requests to make for the template"`
	// description: |
	//   File contains the file request to make in the template
	// examples:
	//   - value: exampleNormalFileRequest
	RequestsFile []*file.Request `yaml:"file,omitempty" json:"file,omitempty" jsonschema:"title=file requests to make,description=File requests to make for the template"`
	// description: |
	//   Network contains the network request to make in the template
	//   WARNING: 'network' will be deprecated and will be removed in a future release. Please use 'tcp' instead.
	// examples:
	//   - value: exampleNormalNetworkRequest
	RequestsNetwork []*network.Request `yaml:"network,omitempty" json:"network,omitempty" jsonschema:"title=network requests to make,description=Network requests to make for the template"`
	// description: |
	//   TCP contains the network request to make in the template
	// examples:
	//   - value: exampleNormalNetworkRequest
	// RequestsWithTCP is placeholder(internal) only, and should not be used instead use RequestsNetwork
	// Deprecated: Use RequestsNetwork instead.
	RequestsWithTCP []*network.Request `yaml:"tcp,omitempty" json:"tcp,omitempty" jsonschema:"title=network(tcp) requests to make,description=Network requests to make for the template"`
	// description: |
	//   Headless contains the headless request to make in the template.
	RequestsHeadless []*headless.Request `yaml:"headless,omitempty" json:"headless,omitempty" jsonschema:"title=headless requests to make,description=Headless requests to make for the template"`
	// description: |
	//   SSL contains the SSL request to make in the template.
	RequestsSSL []*ssl.Request `yaml:"ssl,omitempty" json:"ssl,omitempty" jsonschema:"title=ssl requests to make,description=SSL requests to make for the template"`
	// description: |
	//   Websocket contains the Websocket request to make in the template.
	RequestsWebsocket []*websocket.Request `yaml:"websocket,omitempty" json:"websocket,omitempty" jsonschema:"title=websocket requests to make,description=Websocket requests to make for the template"`
	// description: |
	//   WHOIS contains the WHOIS request to make in the template.
	RequestsWHOIS []*whois.Request `yaml:"whois,omitempty" json:"whois,omitempty" jsonschema:"title=whois requests to make,description=WHOIS requests to make for the template"`
	// description: |
	//   Code contains code snippets.
	RequestsCode []*code.Request `yaml:"code,omitempty" json:"code,omitempty" jsonschema:"title=code snippets to make,description=Code snippets"`
	// description: |
	//   Javascript contains the javascript request to make in the template.
	RequestsJavascript []*javascript.Request `yaml:"javascript,omitempty" json:"javascript,omitempty" jsonschema:"title=javascript requests to make,description=Javascript requests to make for the template"`

	// description: |
	//   Workflows is a yaml based workflow declaration code.
	workflows.Workflow `yaml:",inline,omitempty" jsonschema:"title=workflows to run,description=Workflows to run for the template"`
	CompiledWorkflow   *workflows.Workflow `yaml:"-" json:"-" jsonschema:"-"`

	// description: |
	//   Self Contained marks Requests for the template as self-contained
	SelfContained bool `yaml:"self-contained,omitempty" json:"self-contained,omitempty" jsonschema:"title=mark requests as self-contained,description=Mark Requests for the template as self-contained"`
	// description: |
	//  Stop execution once first match is found
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty" jsonschema:"title=stop at first match,description=Stop at first match for the template"`

	// description: |
	//   Signature is the request signature method
	// values:
	//   - "AWS"
	Signature http.SignatureTypeHolder `yaml:"signature,omitempty" json:"signature,omitempty" jsonschema:"title=signature is the http request signature method,description=Signature is the HTTP Request signature Method,enum=AWS"`

	// description: |
	//   Variables contains any variables for the current request.
	Variables variables.Variable `yaml:"variables,omitempty" json:"variables,omitempty" jsonschema:"title=variables for the http request,description=Variables contains any variables for the current request"`

	// description: |
	//   Constants contains any scalar constant for the current template
	Constants map[string]interface{} `yaml:"constants,omitempty" json:"constants,omitempty" jsonschema:"title=constant for the template,description=constants contains any constant for the template"`

	// TotalRequests is the total number of requests for the template.
	TotalRequests int `yaml:"-" json:"-"`
	// Executer is the actual template executor for running template requests
	Executer protocols.Executer `yaml:"-" json:"-"`

	Path string `yaml:"-" json:"-"`

	// Verified defines if the template signature is digitally verified
	Verified bool `yaml:"-" json:"-"`

	// RequestsQueue contains all template requests in order (both protocol & request order)
	RequestsQueue []protocols.Request `yaml:"-" json:"-"`

	// ImportedFiles contains list of files whose contents are imported after template was compiled
	ImportedFiles []string `yaml:"-" json:"-"`
}
