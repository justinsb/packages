package ini

import (
	"fmt"
	"io"
	"sort"
)

type File struct {
	sections map[string]*Section
}

type Section struct {
	name   string
	values map[string]*Value
}

type Value struct {
	Key   string
	Value string
}

func New() *File {
	return &File{
		sections: make(map[string]*Section),
	}
}

func (i *File) Section(key string) *Section {
	section, ok := i.sections[key]
	if !ok {
		section = &Section{
			name:   key,
			values: make(map[string]*Value),
		}
		i.sections[key] = section
	}
	return section
}
func (i *Section) Set(key string, value string) {
	entry, ok := i.values[key]
	if !ok {
		entry = &Value{Key: key}
		i.values[key] = entry
	}
	entry.Value = value
}

func (i *File) WriteTo(w io.Writer) error {
	var keys []string
	for k := range i.sections {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		section := i.sections[k]
		if err := section.WriteTo(w); err != nil {
			return err
		}
	}
	return nil
}

func (i *Section) WriteTo(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "[%s]\n", i.name); err != nil {
		return err
	}
	var keys []string
	for k := range i.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		value := i.values[k]
		if err := value.WriteTo(w); err != nil {
			return err
		}
	}
	return nil
}
func (i *Value) WriteTo(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "%s=%s\n", i.Key, i.Value); err != nil {
		return err
	}
	return nil
}
