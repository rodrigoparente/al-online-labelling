clean:
	rm -rf dist/; \
	rm -rf build/; \
	rm -rf minified/; \
	rm -f al-online-labelling.spec

minify:
	mkdir minified; \
	ls *.py | while read -r file; do pyminify $$file > minified/$$file; done

build: minify
	pyinstaller \
	--add-data 'datasets/initial.csv:datasets' \
	--add-data 'datasets/pool.csv:datasets' \
	--add-data 'datasets/test.csv:datasets' \
	--name 'al-online-labelling' \
	--onefile --windowed minified/main.py

run:
	./dist/al-online-labelling
