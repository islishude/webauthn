package main

import "testing"

func TestDecodeModules(t *testing.T) {
	modules, err := decodeModules([]byte("{\"Path\":\"main\",\"Main\":true}\n{\"Path\":\"dependency\",\"Version\":\"v1.0.0\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(modules) != 2 || !modules[0].Main || modules[1].Path != "dependency" || modules[1].Version != "v1.0.0" {
		t.Fatalf("modules = %+v", modules)
	}
	for _, data := range []string{`{"Path":"a","Path":"b"}`, `{"Path":"a"} garbage`, "{\"Path\":\"\xff\"}"} {
		if _, err := decodeModules([]byte(data)); err == nil {
			t.Fatalf("accepted %q", data)
		}
	}
}
