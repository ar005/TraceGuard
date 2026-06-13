// internal/api/openapi.go — serves the OpenAPI 3.0 spec and Swagger UI.

package api

import (
	_ "embed"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

//go:embed docs/openapi.yaml
var openapiYAML []byte

func (s *Server) handleOpenAPIYAML(c *gin.Context) {
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", openapiYAML)
}

func (s *Server) handleOpenAPIJSON(c *gin.Context) {
	var doc any
	if err := yaml.Unmarshal(openapiYAML, &doc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse spec"})
		return
	}
	doc = convertYAMLtoJSON(doc)
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal spec"})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", b)
}

func (s *Server) handleSwaggerUI(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(swaggerUIHTML))
}

// convertYAMLtoJSON recursively converts map[string]any from yaml.v3
// (which uses map[string]interface{}) to JSON-compatible types.
func convertYAMLtoJSON(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			out[k] = convertYAMLtoJSON(vv)
		}
		return out
	case []any:
		for i, vv := range val {
			val[i] = convertYAMLtoJSON(vv)
		}
		return val
	default:
		return val
	}
}

const swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>TraceGuard API — Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
  <style>
    body { margin: 0; }
    #swagger-ui .topbar { background: #0f172a; }
    #swagger-ui .topbar-wrapper img { content: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>'); height:36px; }
    #swagger-ui .topbar-wrapper a span { display: none; }
  </style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
SwaggerUIBundle({
  url: "/api/v1/openapi.json",
  dom_id: "#swagger-ui",
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  layout: "BaseLayout",
  deepLinking: true,
  tryItOutEnabled: true,
  persistAuthorization: true,
});
</script>
</body>
</html>`
