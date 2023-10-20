echo "changing execution policy to run virtual environment"
call Set-ExecutionPolicy Unrestricted -scope process
echo "activating virtual environment..."
call .\al-online-labelling\Scripts\activate
echo "building app executable..."
call pyinstaller --add-data="datasets/initial.csv;datasets" ^
--add-data="datasets/pool.csv;datasets" ^
--add-data="datasets/test.csv;datasets" ^
--name="al-online-labelling" ^
--onefile minified/main.py