package configload

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/avenga/couper/config"
	"github.com/avenga/couper/config/configload/collect"
	"github.com/avenga/couper/config/parser"
	"github.com/avenga/couper/config/reader"
	"github.com/avenga/couper/errors"
	"github.com/avenga/couper/eval"
	"github.com/avenga/couper/eval/lib"
	"github.com/avenga/couper/internal/seetie"
)

const (
	api          = "api"
	backend      = "backend"
	definitions  = "definitions"
	errorHandler = "error_handler"
	nameLabel    = "name"
	oauth2       = "oauth2"
	proxy        = "proxy"
	request      = "request"
	server       = "server"
	settings     = "settings"
	// defaultNameLabel maps the hcl label attr 'name'.
	defaultNameLabel = "default"
)

var regexProxyRequestLabel = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
var defaultsConfig *config.Defaults
var evalContext *eval.Context
var envContext *hcl.EvalContext

func init() {
	envContext = eval.NewContext(nil, nil).HCLContext()
}

func updateContext(body hcl.Body, srcBytes [][]byte) hcl.Diagnostics {
	defaultsBlock := &config.DefaultsBlock{}
	if diags := gohcl.DecodeBody(body, nil, defaultsBlock); diags.HasErrors() {
		return diags
	}

	// We need the "envContext" to be able to resolve abs pathes in the config.
	defaultsConfig = defaultsBlock.Defaults
	evalContext = eval.NewContext(srcBytes, defaultsConfig)
	envContext = evalContext.HCLContext()

	return nil
}

func parseFile(filePath string, srcBytes *[][]byte) (*hcl.File, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	*srcBytes = append(*srcBytes, src)

	parsed, diags := hclparse.NewParser().ParseHCLFile(filePath)
	if diags.HasErrors() {
		return nil, diags
	}

	return parsed, nil
}

// SetWorkingDirectory sets the working directory to the given configuration file path.
func SetWorkingDirectory(configFile string) (string, error) {
	if err := os.Chdir(filepath.Dir(configFile)); err != nil {
		return "", err
	}

	return os.Getwd()
}

func LoadFiles(filePath, dirPath string) (*config.Couper, error) {
	var (
		srcBytes     [][]byte
		parsedBodies []*hclsyntax.Body
		hasIndexHCL  bool
	)

	if dirPath != "" {
		dir, err := filepath.Abs(dirPath)
		if err != nil {
			return nil, err
		}

		dirPath = dir

		// ReadDir ... returns a list ... sorted by filename.
		listing, err := ioutil.ReadDir(dirPath)
		if err != nil {
			return nil, err
		}

		for _, file := range listing {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".hcl") {
				continue
			}

			if file.Name() == config.DefaultFilename {
				hasIndexHCL = true
				continue
			}

			parsed, err := parseFile(dirPath+"/"+file.Name(), &srcBytes)
			if err != nil {
				return nil, err
			}

			parsedBodies = append(parsedBodies, parsed.Body.(*hclsyntax.Body))
		}
	}

	if hasIndexHCL {
		parsed, err := parseFile(dirPath+"/"+config.DefaultFilename, &srcBytes)
		if err != nil {
			return nil, err
		}

		parsedBodies = append([]*hclsyntax.Body{parsed.Body.(*hclsyntax.Body)}, parsedBodies...)
	}
	if filePath != "" {
		filePath, err := filepath.Abs(filePath)
		if err != nil {
			return nil, err
		}

		parsed, err := parseFile(filePath, &srcBytes)
		if err != nil {
			return nil, err
		}

		parsedBodies = append([]*hclsyntax.Body{parsed.Body.(*hclsyntax.Body)}, parsedBodies...)

		_, err = SetWorkingDirectory(filePath)
		if err != nil {
			return nil, err
		}
	} else {
		_, err := SetWorkingDirectory(dirPath + "/dummy.hcl")
		if err != nil {
			return nil, err
		}
	}

	if len(srcBytes) == 0 {
		return nil, fmt.Errorf("missing configuration files")
	}

	defaults := mergeAttributes("defaults", parsedBodies)

	defs := &hclsyntax.Body{
		Blocks: hclsyntax.Blocks{defaults},
	}

	if diags := updateContext(defs, srcBytes); diags.HasErrors() {
		return nil, diags
	}

	settings := mergeAttributes("settings", parsedBodies)

	definitions, err := mergeDefinitions(parsedBodies)
	if err != nil {
		return nil, err
	}

	servers, err := mergeServers(parsedBodies)
	if err != nil {
		return nil, err
	}

	configBlocks := servers
	configBlocks = append(configBlocks, definitions)
	configBlocks = append(configBlocks, defaults)
	configBlocks = append(configBlocks, settings)

	configBody := &hclsyntax.Body{
		Blocks: configBlocks,
	}

	return LoadConfig(configBody, filepath.Base(filePath), dirPath)
}

func LoadBytes(src []byte, filename string) (*config.Couper, error) {
	hclBody, diags := parser.Load(src, filename)
	if diags.HasErrors() {
		return nil, diags
	}

	if diags := updateContext(hclBody, [][]byte{src}); diags.HasErrors() {
		return nil, diags
	}

	return LoadConfig(hclBody, filename, "")
}

func LoadConfig(body hcl.Body, filename, dirPath string) (*config.Couper, error) {
	if diags := ValidateConfigSchema(body, &config.Couper{}); diags.HasErrors() {
		return nil, diags
	}

	defaults := config.DefaultSettings
	defaults.AcceptForwarded = &config.AcceptForwarded{}

	couperConfig := &config.Couper{
		Context:     evalContext,
		Definitions: &config.Definitions{},
		Defaults:    defaultsConfig,
		Filename:    filename,
		Dirpath:     dirPath,
		Settings:    &defaults,
	}

	schema, _ := gohcl.ImpliedBodySchema(couperConfig)
	content, diags := body.Content(schema)
	if content == nil {
		return nil, fmt.Errorf("invalid configuration: %w", diags)
	}

	// Read possible reference definitions first. Those are the
	// base for refinement merges during server block read out.
	var definedBackends Backends
	var err error

	for _, outerBlock := range content.Blocks {
		switch outerBlock.Type {
		case definitions:
			backendContent, leftOver, diags := outerBlock.Body.PartialContent(backendBlockSchema)
			if diags.HasErrors() {
				return nil, diags
			}

			if backendContent != nil {
				for _, be := range backendContent.Blocks {
					name := be.Labels[0]
					ref, _ := definedBackends.WithName(name)
					if ref != nil {
						return nil, hcl.Diagnostics{&hcl.Diagnostic{
							Severity: hcl.DiagError,
							Summary:  fmt.Sprintf("duplicate backend name: %q", name),
							Subject:  &be.LabelRanges[0],
						}}
					}

					definedBackends = append(definedBackends, NewBackend(name, be.Body))
				}
			}

			if diags = gohcl.DecodeBody(leftOver, envContext, couperConfig.Definitions); diags.HasErrors() {
				return nil, diags
			}

			for _, oauth2Config := range couperConfig.Definitions.OAuth2AC {
				bodyContent, _, diags := oauth2Config.HCLBody().PartialContent(oauth2Config.Schema(true))
				if diags.HasErrors() {
					return nil, diags
				}
				oauth2Config.BodyContent = bodyContent

				oauth2Config.Backend, err = newBackend(definedBackends, oauth2Config)
				if err != nil {
					return nil, err
				}
			}

			for _, oidcConfig := range couperConfig.Definitions.OIDC {
				bodyContent, _, diags := oidcConfig.HCLBody().PartialContent(oidcConfig.Schema(true))
				if diags.HasErrors() {
					return nil, diags
				}
				oidcConfig.BodyContent = bodyContent

				oidcConfig.Backend, err = newBackend(definedBackends, oidcConfig)
				if err != nil {
					return nil, err
				}
			}
			// TODO remove for version 1.8
			for _, oidcConfig := range couperConfig.Definitions.BetaOIDC {
				bodyContent, _, diags := oidcConfig.HCLBody().PartialContent(oidcConfig.Schema(true))
				if diags.HasErrors() {
					return nil, diags
				}
				oidcConfig.BodyContent = bodyContent

				oidcConfig.Backend, err = newBackend(definedBackends, oidcConfig)
				if err != nil {
					return nil, err
				}
			}

			for _, jwtConfig := range couperConfig.Definitions.JWT {
				if jwtConfig.JWKsURL != "" {
					bodyContent, _, diags := jwtConfig.HCLBody().PartialContent(jwtConfig.Schema(true))
					if diags.HasErrors() {
						return nil, diags
					}
					jwtConfig.BodyContent = bodyContent

					jwtConfig.Backend, err = newBackend(definedBackends, jwtConfig)
					if err != nil {
						return nil, err
					}

					jwtConfig.BackendName = ""
				}
				if err = jwtConfig.Check(); err != nil {
					return nil, errors.Configuration.Label(jwtConfig.Name).With(err)
				}
			}

			acErrorHandler := collect.ErrorHandlerSetters(couperConfig.Definitions)
			if err := configureErrorHandler(acErrorHandler, definedBackends); err != nil {
				return nil, err
			}

		case settings:
			if diags = gohcl.DecodeBody(outerBlock.Body, envContext, couperConfig.Settings); diags.HasErrors() {
				return nil, diags
			}
			if err := couperConfig.Settings.SetAcceptForwarded(); err != nil {
				diag := &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  fmt.Sprintf("invalid accept_forwarded_url: %q", err),
					Subject:  &outerBlock.DefRange,
				}
				return nil, diag
			}
		}
	}

	// Prepare dynamic functions
	for _, profile := range couperConfig.Definitions.JWTSigningProfile {
		if profile.Headers != nil {
			expression, _ := profile.Headers.Value(nil)
			headers := seetie.ValueToMap(expression)

			var errorMessage string
			if _, exists := headers["alg"]; exists {
				errorMessage = `"alg" cannot be set via "headers"`
			} else if _, exists := headers["typ"]; exists {
				errorMessage = `"typ" cannot be set via "headers"`
			}

			if errorMessage != "" {
				err := fmt.Errorf(errorMessage)
				return nil, errors.Configuration.Label(profile.Name).With(err)
			}
		}

		key, err := reader.ReadFromAttrFile("jwt_signing_profile key", profile.Key, profile.KeyFile)
		if err != nil {
			return nil, errors.Configuration.Label(profile.Name).With(err)
		}
		profile.KeyBytes = key
	}

	for _, saml := range couperConfig.Definitions.SAML {
		metadata, err := reader.ReadFromFile("saml2 idp_metadata_file", saml.IdpMetadataFile)
		if err != nil {
			return nil, errors.Configuration.Label(saml.Name).With(err)
		}
		saml.MetadataBytes = metadata
	}

	jwtSigningConfigs := make(map[string]*lib.JWTSigningConfig)
	for _, profile := range couperConfig.Definitions.JWTSigningProfile {
		if _, exists := jwtSigningConfigs[profile.Name]; exists {
			return nil, errors.Configuration.Messagef("jwt_signing_profile block with label %s already defined", profile.Name)
		}
		signConf, err := lib.NewJWTSigningConfigFromJWTSigningProfile(profile)
		if err != nil {
			return nil, errors.Configuration.Label(profile.Name).With(err)
		}
		jwtSigningConfigs[profile.Name] = signConf
	}
	for _, jwt := range couperConfig.Definitions.JWT {
		signConf, err := lib.NewJWTSigningConfigFromJWT(jwt)
		if err != nil {
			return nil, errors.Configuration.Label(jwt.Name).With(err)
		}
		if signConf != nil {
			if _, exists := jwtSigningConfigs[jwt.Name]; exists {
				return nil, errors.Configuration.Messagef("jwt_signing_profile or jwt with label %s already defined", jwt.Name)
			}
			jwtSigningConfigs[jwt.Name] = signConf
		}
	}

	couperConfig.Context = evalContext.
		WithJWTSigningConfigs(jwtSigningConfigs).
		WithOAuth2AC(couperConfig.Definitions.OAuth2AC).
		WithSAML(couperConfig.Definitions.SAML)

	// Read per server block and merge backend settings which results in a final server configuration.
	for _, serverBlock := range bodyToContent(body).Blocks.OfType(server) {
		serverConfig := &config.Server{}
		if diags = gohcl.DecodeBody(serverBlock.Body, envContext, serverConfig); diags.HasErrors() {
			return nil, diags
		}

		// Set the server name since gohcl.DecodeBody decoded the body and not the block.
		if len(serverBlock.Labels) > 0 {
			serverConfig.Name = serverBlock.Labels[0]
		}

		// Read api blocks and merge backends with server and definitions backends.
		for _, apiBlock := range bodyToContent(serverConfig.Remain).Blocks.OfType(api) {
			apiConfig := &config.API{}
			if diags = gohcl.DecodeBody(apiBlock.Body, envContext, apiConfig); diags.HasErrors() {
				return nil, diags
			}

			if len(apiBlock.Labels) > 0 {
				apiConfig.Name = apiBlock.Labels[0]
			}

			if apiConfig.AllowedMethods != nil && len(apiConfig.AllowedMethods) > 0 {
				if err = validMethods(apiConfig.AllowedMethods, &bodyToContent(apiConfig.Remain).Attributes["allowed_methods"].Range); err != nil {
					return nil, err
				}
			}

			err := refineEndpoints(definedBackends, apiConfig.Endpoints, true)
			if err != nil {
				return nil, err
			}

			apiConfig.CatchAllEndpoint = newCatchAllEndpoint()
			serverConfig.APIs = append(serverConfig.APIs, apiConfig)

			apiErrorHandler := collect.ErrorHandlerSetters(apiConfig)
			if err = configureErrorHandler(apiErrorHandler, definedBackends); err != nil {
				return nil, err
			}
		}

		// standalone endpoints
		err := refineEndpoints(definedBackends, serverConfig.Endpoints, true)
		if err != nil {
			return nil, err
		}

		couperConfig.Servers = append(couperConfig.Servers, serverConfig)
	}

	if len(couperConfig.Servers) == 0 {
		return nil, fmt.Errorf("configuration error: missing 'server' block")
	}

	return couperConfig, nil
}
