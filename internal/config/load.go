package config

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"go.yaml.in/yaml/v3"
)

//go:embed default.yaml
var defaultFile []byte

// Load returns the configuration in the YAML file at path, or in the built-in default.yaml when path is empty, with the storage URL from the environment.
// The file is the whole configuration: every field must be set, and nothing else may be.
func Load(path string) (*Config, error) {
	data := defaultFile
	if path != "" {
		var err error
		if data, err = os.ReadFile(path); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}

	cfg, err := decode(data)
	if err != nil {
		return nil, err
	}
	cfg.Storage.URL = os.Getenv("SEAL_GATE_STORAGE_URL")
	return cfg, nil
}

func decode(data []byte) (*Config, error) {
	cfg := &Config{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	// An empty file has no document, which the decoder reports as io.EOF; the field check below refuses it.
	if err := decoder.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFile, err)
	}
	if err := decoder.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: more than one document", ErrInvalidFile)
	}

	// Decoded again as a tree, since a struct cannot tell a field left out from one set to its zero value.
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFile, err)
	}
	if err := refuseReuse(&document); err != nil {
		return nil, err
	}
	var root *yaml.Node
	if len(document.Content) > 0 {
		root = document.Content[0]
	}
	if err := requireFields(root, reflect.TypeFor[Config](), ""); err != nil {
		return nil, err
	}
	return cfg, nil
}

// requireFields reports the first yaml-tagged field of t that the mapping node leaves out, walking nested structs and lists of them.
func requireFields(node *yaml.Node, t reflect.Type, prefix string) error {
	for field := range t.Fields() {
		key := field.Tag.Get("yaml")
		if key == "" || key == "-" {
			continue
		}
		value := mappingValue(node, key)
		// The decoder leaves a null at the zero value, which would make a blank required: false.
		if value == nil || value.ShortTag() == "!!null" {
			return fmt.Errorf("%w: %s%s", ErrMissingField, prefix, key)
		}
		switch field.Type.Kind() {
		case reflect.String:
			// The decoder takes any scalar's text into a string, so path: 123 would pass as a path.
			if value.ShortTag() != "!!str" {
				return fmt.Errorf("%w: %s%s is not text", ErrInvalidFile, prefix, key)
			}
		case reflect.Struct:
			if err := requireFields(value, field.Type, prefix+key+"."); err != nil {
				return err
			}
		case reflect.Slice:
			if field.Type.Elem().Kind() != reflect.Struct {
				continue
			}
			for i, item := range value.Content {
				if err := requireFields(item, field.Type.Elem(), fmt.Sprintf("%s%s[%d].", prefix, key, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// refuseReuse rejects aliases and merge keys, so the file reads literally and requireFields sees every field where it is written.
func refuseReuse(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.ShortTag() == "!!merge" {
		return fmt.Errorf("%w: line %d: aliases and merge keys are not supported", ErrInvalidFile, node.Line)
	}
	for _, child := range node.Content {
		if err := refuseReuse(child); err != nil {
			return err
		}
	}
	return nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	// A mapping's Content alternates key and value nodes.
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
