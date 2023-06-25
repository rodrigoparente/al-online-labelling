clean:
	rm -r dist/ && rm -r build/ && rm al-online-labelling.spec

build:
	pyinstaller \
	--add-data 'datasets/initial.csv:datasets' \
	--add-data 'datasets/pool.csv:datasets' \
	--add-data 'datasets/test.csv:datasets' \
	--name 'al-online-labelling' \
	--onefile --windowed main.py

run:
	./dist/al-online-labelling