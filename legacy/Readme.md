# network-diag

Network diagnostics based on the OSI model layers. It checks network interfaces (L1/L2), 
ICMP availability (L3), TCP connections (L4), DNS resolution, and HTTP responses (L5-L7).

## Building without Docker

### Linux
```bash
cmake -B build -S .
cmake --build build
./build/network_diag google.com ya.ru
```

### Windows (MSVC, via "Developer Command Prompt" or CMake GUI)
```powershell
cmake -B build -S .
cmake --build build --config Release
.\build\Release\network_diag.exe google.com ya.ru
```

## Building and Running via Docker (for Windows development)

```powershell
# From the project root folder
docker build -t network-diag .
docker run --rm network-diag google.com ya.ru
```

Note: The container sees the network from the perspective of the host running Docker 
(typically a WSL2 virtual machine on Windows). Therefore, if provider-level blocks 
depend specifically on your physical connection, it is better to additionally run the 
exe directly on Windows rather than relying solely on the container.
