# PRINCE: comparação de implementações (protótipo)

Data (UTC): 2026-11-03T20:07:53Z  
CPU: AMD Ryzen 7 5800H with Radeon Graphics  
Compilador: gcc (GCC) 16.2.1 20260810  
Medição: cifra ECB de um buffer de 128 KiB (16384 blocos), melhor de 7 repetições, só o núcleo da cifra (sem OpenSSL).  
Correção: todas as variantes dão exatamente o mesmo ciphertext que `src/ciphers/prince.c`.

## `-O3` (flags atuais do projeto)

| Variante                       |      MB/s | ns/bloco |   ganho |
|---|---:|---:|---:|
| Atual (bit a bit)              |      25.5 |    314.1 |    1.0x |
| Tabelas fundidas               |     162.6 |     49.2 |    6.4x |
| SWAR (1 bloco)                 |      76.9 |    104.0 |    3.0x |
| Bitslice 64-bit (4 blocos)     |     166.5 |     48.0 |    6.5x |
| Bitslice 256-bit (16 blocos)   |     159.3 |     50.2 |    6.3x |

## `-O3 -mavx2`

| Variante                       |      MB/s | ns/bloco |   ganho |
|---|---:|---:|---:|
| Atual (bit a bit)              |      25.9 |    309.1 |    1.0x |
| Tabelas fundidas               |     162.1 |     49.4 |    6.3x |
| SWAR (1 bloco)                 |      79.1 |    101.1 |    3.1x |
| Bitslice 64-bit (4 blocos)     |     170.5 |     46.9 |    6.6x |
| Bitslice 256-bit (16 blocos)   |     453.9 |     17.6 |   17.5x |
