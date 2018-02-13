build:
	ocaml pkg/pkg.ml build

clean:
	ocaml pkg/pkg.ml clean

fuzz: build
	bun -v -i input -o output _build/test/test_x509.native

.PHONY: build
