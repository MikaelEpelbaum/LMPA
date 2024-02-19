## Setup

Simply drop this script (as well as the `gepetto/` folder) into your IDA plugins folder (`$IDAUSR/plugins`). 
By default, on Windows, this should be `%AppData%\Hex-Rays\IDA Pro\plugins` (you may need to create the folder).

You will need to add the required packages to IDA's Python installation for the script to work.
Find which interpreter IDA is using by checking the following registry key: 
`Computer\HKEY_CURRENT_USER\Software\Hex-Rays\IDA` (default on Windows: `%LOCALAPPDATA%\Programs\Python\Python39`).
Finally, with the corresponding interpreter, simply run: 

```
[/path/to/python] -m pip install -r requirements.txt

for more data look at https://github.com/JusticeRage/Gepetto/tree/main/gepetto
