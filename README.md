# post2mpv

HTTP-сервер для управления воспроизведением медиа через `mpv`, `peerflix` и загрузкой через `yt-dlp`.

## Требования

- [mpv](https://mpv.io/)
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) — для действия `download`
- [peerflix](https://github.com/mafintosh/peerflix) — для торрентов
- [vot-cli-live](https://github.com/fantomcheg/vot-cli-live) — для действия `translate` (скрипт `vot` в репозитории, требует `vot-cli-live`)

## Сборка

```bash
go build -o post2mpv .
```

## Запуск

```bash
# Базовый запуск
./post2mpv

# С токеном и портом
./post2mpv --token mysecret --port 7531

# Токен через переменную окружения
POST2MPV_TOKEN=mysecret ./post2mpv

# С конфигурационным файлом
./post2mpv --config /path/to/post2mpv.conf

# Публичный доступ (с токеном обязательно)
./post2mpv --public --token mysecret
```

### Параметры

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `--host` | `127.0.0.1` | Адрес для прослушивания |
| `--port` | `7531` | Порт |
| `--token` | — | Токен авторизации |
| `--public` | `false` | Привязать к `0.0.0.0` |
| `--config` | — | Путь к файлу конфигурации |

### Конфигурационный файл

Формат `KEY=VALUE`, комментарии через `#`.

```ini
POST2MPV_TOKEN=your_secret_token
POST2MPV_HOST=127.0.0.1
POST2MPV_PORT=7531
```

Стандартные пути (проверяются автоматически):
- `/etc/post2mpv/post2mpv.conf`
- `~/.config/post2mpv/post2mpv.conf`

## Установка как пользовательский сервис systemd

```bash
# Установить бинарник и скрипт vot
cp post2mpv ~/.local/bin/post2mpv
cp vot ~/.local/bin/vot
chmod +x ~/.local/bin/vot

# Создать директорию для конфига
mkdir -p ~/.config/post2mpv

# Записать токен в конфиг (рекомендуется)
echo "POST2MPV_TOKEN=your_secret_token" > ~/.config/post2mpv/post2mpv.conf

# Установить unit-файл
mkdir -p ~/.config/systemd/user
cp post2mpv.service ~/.config/systemd/user/post2mpv.service

# Включить и запустить
systemctl --user daemon-reload
systemctl --user enable --now post2mpv
```

### Управление сервисом

```bash
systemctl --user status post2mpv
systemctl --user restart post2mpv
systemctl --user stop post2mpv

# Логи всего сервиса
journalctl --user -u post2mpv -f

# Логи конкретного задания
journalctl --user -u post2mpv -g '<job_id>'
```

> Чтобы сервис запускался без активного сеанса пользователя:
> ```bash
> loginctl enable-linger $USER
> ```

### X11 / Wayland

`mpv` требует доступа к дисплею. В зависимости от окружения отредактируйте `post2mpv.service`:

**X11:**
```ini
Environment=DISPLAY=:0
```

**Wayland:**
```ini
Environment=WAYLAND_DISPLAY=wayland-0
```

**Определить текущее окружение:**
```bash
echo $XDG_SESSION_TYPE   # x11 или wayland
echo $WAYLAND_DISPLAY    # wayland-0 или wayland-1
echo $DISPLAY            # :0 или :1
```

После изменения unit-файла:
```bash
systemctl --user daemon-reload && systemctl --user restart post2mpv
```

## API

### POST /

**Заголовки:**
```
Content-Type: application/json
X-POST2MPV-TOKEN: <token>   # если токен задан
```

**Тело запроса:**
```json
{
  "url": "https://example.com/video.mp4",
  "action": "play",
  "params": ["--volume=50"]
}
```

| Поле | Обязательно | Описание |
|------|-------------|----------|
| `url` | да | URL видео, торрент-файла или magnet-ссылка |
| `action` | нет | `play` (по умолчанию), `download`, `translate` |
| `params` | нет | Дополнительные аргументы для команды |
| `output` | нет | Путь вывода для `download` (`-o` в yt-dlp) |

**Ответ:**
```json
{
  "status": "ok",
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "play"
}
```

### Действия

| action | Команда | Примечание |
|--------|---------|-----------|
| `play` | `mpv` | Для magnet/`.torrent` — `peerflix` |
| `download` | `yt-dlp` | |
| `translate` | `vot` | |

### Примеры

```bash
# Воспроизвести видео
curl -X POST http://localhost:7531 \
  -H 'Content-Type: application/json' \
  -H 'X-POST2MPV-TOKEN: mysecret' \
  -d '{"url": "https://youtu.be/dQw4w9WgXcQ", "action": "play"}'

# Скачать с указанием пути
curl -X POST http://localhost:7531 \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://youtu.be/dQw4w9WgXcQ", "action": "download", "output": "~/Downloads/%(title)s.%(ext)s"}'

# Торрент
curl -X POST http://localhost:7531 \
  -H 'Content-Type: application/json' \
  -d '{"url": "magnet:?xt=urn:btih:...", "action": "play"}'
```
