OUTPUT_DIR = ../js/plugin

.PHONY: build
build:
	cargo build --target=wasm32-wasip2 --release
	# Fix the import namespace from $root::call to host::call for Kubewarden compatibility
	wasm-tools print target/wasm32-wasip2/release/javy_plugin_kubewarden.wasm > component.wat
	sed 's/(import "$$root" "call"/(import "host" "call"/g' component.wat > component-fixed.wat
	wasm-tools parse component-fixed.wat -o component-fixed.wasm
	javy init-plugin component-fixed.wasm -o $(OUTPUT_DIR)/javy-plugin-kubewarden.wasm
	# Clean up temporary files
	rm -f component.wat component-fixed.wat component-fixed.wasm

.PHONY: clean
clean:
	cargo clean
