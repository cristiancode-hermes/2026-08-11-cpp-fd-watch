# cpp-fd-watch — File Descriptor Watch (Linux)

Analizador de **file descriptors** de Linux en **C++23** que lee `/proc/sys/fs/file-nr`, `/proc/sys/fs/nr_open` y, por proceso, `/proc/<pid>/{fd,comm,limits,stat}` para mostrar el uso de descriptores del sistema: fds asignados vs `nr_open`, los procesos que más descriptores consumen, sus límites soft/hard y la presión por límite. Cero dependencias externas: compilación directa con `g++`.

## Features

- **Estado global del sistema** desde `/proc/sys/fs/file-nr`: fds asignados, libres, `file-max` y el techo práctico `nr_open` con % de utilización
- **Top consumidores por proceso**: conteo real de entradas en `/proc/<pid>/fd` (symlinks incluidos), nombre desde `/proc/<pid>/comm`
- **Límites soft/hard** por proceso desde `/proc/<pid>/limits` (`Max open files`), con % del límite soft y aviso de presión (≥80%)
- **Distribución de estados** de proceso (running/sleeping/disk/zombie/idle) desde `/proc/<pid>/stat`
- **Modo watch** (`--watch N`): tasas delta en vivo cada N segundos (fds asignados/s, fds de procesos/s) con refresco en pantalla
- Salida **JSON** completa para scripting (`--json`) con estructura `{system, processes[], summary}`
- Filtros `--top N` y `--min N` (solo procesos con fds ≥ N)
- Manejo elegante de procesos sin acceso (`EACCES` en `/proc/<pid>/fd` se cuenta como "without access", no rompe el scan)
- Colores ANSI (desactivables con `--no-color`)
- 17 tests de auto-verificación (`--selftest`): parseo sintético de file-nr/limits/stat, formateo, escape JSON y smoke tests contra `/proc` real

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o fd-watch
```

## Usage

```bash
./fd-watch                      # snapshot: sistema + top 10 consumidores
./fd-watch --top 5              # solo los 5 procesos con más fds
./fd-watch --min 10             # solo procesos con >= 10 fds
./fd-watch --watch 2            # tasas delta en vivo cada 2s
./fd-watch --json               # JSON completo para scripting
./fd-watch --no-color           # sin ANSI (pipes/logs)
./fd-watch --selftest           # auto-verificación
```

## Ejemplo

```
FD WATCH — Linux file descriptor usage  (/proc/sys/fs/file-nr + /proc/<pid>/fd)
------------------------------------------------------------------------------
SYSTEM FDS      allocated 3.072   unused 0   file-max 9.22E   nr_open 1.05M   0.3%
PROCESSES      76 scanned  1 without access   total fds 1.324   avg 17.4/proc
STATES         running 1   sleeping 75   disk 0   zombie 0   idle 0   other 0

TOP FD CONSUMERS  (min 0 fds, showing 5)
 PID     NAME                        FDS     SOFT LIMIT   %LIMIT  ST  BAR
710060  hermes                         70        1.024     6.8%   S   ||||||||||||||||||||
    12  hermes                         68        1.024     6.6%   S   |||||||||||||||||||.
   114  forgejo                        27      524.287     0.0%   S   ||||||||............
507442  hermes                         25        1.024     2.4%   S   |||||||.............
   354  node-MainThread                21      524.288     0.0%   S   ||||||..............
```

## Fuentes de datos

| Archivo | Campos usados |
|---|---|
| `/proc/sys/fs/file-nr` | fds asignados, libres, `file-max` |
| `/proc/sys/fs/nr_open` | techo por proceso (base del % de utilización) |
| `/proc/<pid>/fd/` | nº de entradas (un fd por proceso) |
| `/proc/<pid>/comm` | nombre del proceso |
| `/proc/<pid>/limits` | `Max open files` soft/hard |
| `/proc/<pid>/stat` | estado (R/S/D/Z/I) |

## Notas

- `file-max` en kernels modernos es `2^63-1` (auto-tuneado); el límite práctico es `nr_open` (por defecto 1.048.576).
- El conteo de fds incluye sockets, pipes, epoll fds y archivos abiertos: es el uso real del proceso.
- Procesos de otros usuarios (o en contenedores sin CAP_SYS_PTRACE) pueden dar `EACCES` al listar `/proc/<pid>/fd`; se reportan como "without access".
