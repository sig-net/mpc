SVG_FILES := $(wildcard *.svg)

# Default target: regenerate all SVGs
all: $(SVG_FILES)

# Convert a DOT file to an SVG file using graphviz
# If you don't have `dot`:
# sudo apt install graphviz
%.svg: %.dot
	dot -Tsvg $< > $@