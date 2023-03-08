package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

func main() {
	pa, err := newApiParser().parse(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	out, err := os.Create(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	newCodeGen(pa, out).Gen()
}

type codeGen struct {
	api *parsedApi
	out io.Writer
}

func newCodeGen(api *parsedApi, out io.Writer) *codeGen {
	return &codeGen{
		api,
		out,
	}
}

func (cg *codeGen) Gen() {
	cg.writeHeader()

	serveHTTPTpl := cg.newServeHTTPTpl()
	handlerTpl := cg.newHandlerTpl()
	validatorTpl := cg.newValidatorTpl()

	for _, h := range cg.api.apiHandlers {
		serveHTTPTpl.Execute(cg.out, h)

		for _, m := range h.ApiFuncs {
			handlerTpl.Execute(cg.out, m)
		}
	}

	for _, v := range cg.api.valStructs {
		validatorTpl.Execute(cg.out, v)
	}
}

func (cg *codeGen) writeHeader() {
	fmt.Fprintf(cg.out, `package %s
import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)`, cg.api.name)
}

func (cg *codeGen) newHandlerTpl() *template.Template {
	return template.Must(template.New("handlerTpl").Parse(`
func (h *{{ .HandlerName }}) handler{{ .Name }}(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	{{ if .Api.Auth -}}
	if r.Header.Get("X-Auth") != "100500" {
		return nil, ApiError{http.StatusForbidden, fmt.Errorf("unauthorized")}
	}
	{{- end }}
	{{ if .Api.Method -}}
	if r.Method != "{{ .Api.Method }}" {
		return nil, ApiError{http.StatusNotAcceptable, fmt.Errorf("bad method")}
	}
	{{ end }}
	var params url.Values
	if r.Method == "GET" {
		params = r.URL.Query()
	} else {
		body, _ := ioutil.ReadAll(r.Body)
		params, _ = url.ParseQuery(string(body))
	}
	in, err := new{{ .RequestStructName }}(params)
	if err != nil {
		return nil, err
	}
	return h.{{ .Name }}(r.Context(), in)
}
`))
}

func (cg *codeGen) newValidatorTpl() *template.Template {
	return template.Must(template.New("validatorTpl").Parse(`
func new{{ .Name }}(v url.Values) ({{ .Name }}, error) {
	var err error
	s := {{ .Name }}{}
	{{ range .Fields }}
	
	{{- if eq .Type "Int" }}
	s.{{ .Name }}, err = strconv.Atoi(v.Get("{{ .Rules.ParamName }}"))
	if err != nil {
		return s, ApiError{http.StatusBadRequest, fmt.Errorf("{{ .Rules.ParamName }} must be int")}
	}
	{{ else }}
	s.{{ .Name }} = v.Get("{{ .Rules.ParamName }}")
	{{ end }}
	{{ if .Rules.Default }}
	if s.{{ .Name }} == "" {
		s.{{ .Name }} = "{{ .Rules.Default }}"
	}
	{{ end }}
	{{ if .Rules.Required }}
	if s.{{ .Name }} == "" {
		return s, ApiError{http.StatusBadRequest, fmt.Errorf("{{ .Rules.ParamName }} must me not empty")}
	}
	{{ end }}
	{{ if and .Rules.Min (eq .Type "Int") }}
	if s.{{ .Name }} < {{ .Rules.MinValue }} {
		return s, ApiError{http.StatusBadRequest, fmt.Errorf("{{ .Rules.ParamName }} must be >= {{ .Rules.MinValue }}")}
	}
	{{ end }}
	{{ if and .Rules.Min (eq .Type "String") }}
	if len(s.{{ .Name }}) < {{ .Rules.MinValue }} {
		return s, ApiError{http.StatusBadRequest, fmt.Errorf("{{ .Rules.ParamName }} len must be >= {{ .Rules.MinValue }}")}
	}
	{{ end }}
	{{ if and .Rules.Max (eq .Type "Int") }}
	if s.{{ .Name }} > {{ .Rules.MaxValue }} {
		return s, ApiError{http.StatusBadRequest, fmt.Errorf("{{ .Rules.ParamName }} must be <= {{ .Rules.MaxValue }}")}
	}
	{{ end }}
	{{ if and .Rules.Max (eq .Type "String") }}
	if len(s.{{ .Name }}) > {{ .Rules.MaxValue }} {
		return s, ApiError{http.StatusBadRequest, fmt.Errorf("{{ .Rules.ParamName }} len must be <= {{ .Rules.MaxValue }}")}
	}
	{{ end }}
	{{ if .Rules.Enum }}
	enum{{ .Name }}Valid := false
	enum{{ .Name }} := []string{ {{ range $index, $element := .Rules.Enum }}{{ if $index }}, {{ end }}"{{ $element }}"{{ end }} }
	for _, valid := range enum{{ .Name }} {
		if valid == s.{{ .Name }} {
			enum{{ .Name }}Valid = true
			break
		}
	}
	if !enum{{ .Name }}Valid {
		return s, ApiError{http.StatusBadRequest, fmt.Errorf("{{ .Rules.ParamName }} must be one of [%s]", strings.Join(enum{{ .Name }}, ", "))}
	}
	{{ end }}
	{{ end }}
	return s, err
}
`))
}

func (cg *codeGen) newServeHTTPTpl() *template.Template {
	return template.Must(template.New("serveHttpTpl").Parse(`
func (h* {{.Name}}) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		res interface{}
		err error
	)
	
	switch r.URL.Path {
		{{ range .ApiFuncs }}case "{{ .Api.Url }}":
			res, err = h.handler{{ .Name }}(w, r)
		{{ end }}default:
			err = ApiError{Err: fmt.Errorf("unknown method"), HTTPStatus: http.StatusNotFound}
	}

	response := struct {
		Data  interface{} ` + "`" + `json:"response,omitempty"` + "`" + `
		Error string      ` + "`" + `json:"error"` + "`" + `
	}{}
	if err == nil {
		response.Data = res
	} else {
		response.Error = err.Error()
		if errApi, ok := err.(ApiError); ok {
			w.WriteHeader(errApi.HTTPStatus)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	jsonResponse, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}
`))
}

type apiParser struct {
	apigenPrefix   string
	matchValidator *regexp.Regexp
}

func newApiParser() *apiParser {
	return &apiParser{
		apigenPrefix:   "// apigen:api",
		matchValidator: regexp.MustCompile("`apivalidator:\"(.*)\"`"),
	}
}

type parsedApi struct {
	name        string
	apiHandlers map[string]*apiHandler
	valStructs  map[string]*valStruct
}

type apiHandler struct {
	Name     string
	ApiFuncs []apiFunc
}

type apiFunc struct {
	Name              string
	HandlerName       string
	RequestStructName string
	Api               apiMeta
}

type apiMeta struct {
	Url    string
	Auth   bool
	Method string
}

type valStruct struct {
	Name   string
	Fields []valField
}

type valField struct {
	Name  string
	Type  string
	Rules valRules
}

type valRules struct {
	ParamName string
	Required  bool
	Min       bool
	MinValue  int
	Max       bool
	MaxValue  int
	Enum      []string
	Default   string
}

func (p *apiParser) parse(filename string) (*parsedApi, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, parser.ParseComments)

	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	api := &parsedApi{
		name:        parsed.Name.Name,
		apiHandlers: map[string]*apiHandler{},
		valStructs:  map[string]*valStruct{},
	}

	for _, decl := range parsed.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			p.parseFunc(decl, api)
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok {
					if st, ok := ts.Type.(*ast.StructType); ok {
						p.parseStruct(st, api, ts.Name.Name)
					}
				}
			}
		}
	}
	return api, nil
}

func (p *apiParser) parseFunc(decl *ast.FuncDecl, api *parsedApi) {
	if decl.Doc == nil {
		return
	}

	meta := apiMeta{}
	for _, doc := range decl.Doc.List {
		if strings.HasPrefix(doc.Text, p.apigenPrefix) {
			apiDoc := doc.Text[len(p.apigenPrefix):]
			if err := json.Unmarshal([]byte(apiDoc), &meta); err == nil {
				break
			}
		}
	}

	if meta.Url != "" {
		if structName := getRecvStruct(decl); structName != "" {
			if _, ok := api.apiHandlers[structName]; !ok {
				api.apiHandlers[structName] = &apiHandler{
					Name: structName,
				}
			}

			if st, ok := decl.Type.Params.List[1].Type.(*ast.Ident); ok {
				ah := api.apiHandlers[structName]
				ah.ApiFuncs = append(ah.ApiFuncs, apiFunc{
					Name:              decl.Name.Name,
					HandlerName:       structName,
					RequestStructName: st.Name,
					Api:               meta,
				})
			}
		}
	}
}

func getRecvStruct(fd *ast.FuncDecl) string {
	if fd.Recv == nil {
		return ""
	}

	for _, f := range fd.Recv.List {
		if f, ok := f.Type.(*ast.StarExpr); ok {
			if f, ok := f.X.(*ast.Ident); ok {
				return f.Name
			}
		}
		if f, ok := f.Type.(*ast.Ident); ok {
			return f.Name
		}
	}
	return ""
}

func (p *apiParser) parseStruct(st *ast.StructType, api *parsedApi, name string) {
	if st.Fields == nil {
		return
	}

	for _, f := range st.Fields.List {
		if f.Tag == nil {
			continue
		}
		if match := p.matchValidator.FindStringSubmatch(f.Tag.Value); len(match) > 0 {
			if _, ok := api.valStructs[name]; !ok {
				api.valStructs[name] = &valStruct{
					Name: name,
				}
			}

			valRules := &valRules{
				ParamName: strings.ToLower(f.Names[0].Name),
			}

			for _, rule := range strings.Split(match[1], ",") {
				ruleConfig := strings.Split(rule, "=")

				switch ruleConfig[0] {
				case "required":
					valRules.Required = true
				case "paramname":
					valRules.ParamName = ruleConfig[1]
				case "min":
					valRules.Min = true
					valRules.MinValue, _ = strconv.Atoi(ruleConfig[1])
				case "max":
					valRules.Max = true
					valRules.MaxValue, _ = strconv.Atoi(ruleConfig[1])
				case "enum":
					valRules.Enum = strings.Split(ruleConfig[1], "|")
				case "default":
					valRules.Default = ruleConfig[1]
				}
			}

			api.valStructs[name].Fields = append(api.valStructs[name].Fields, valField{
				Name:  f.Names[0].Name,
				Type:  strings.Title(f.Type.(*ast.Ident).Name),
				Rules: *valRules,
			})
		}
	}
}
