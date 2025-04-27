# SSH Config Editor 🛠️🔐

Удобный графический редактор для управления SSH-конфигурацией (`~/.ssh/config`) с помощью интуитивно понятного интерфейса на PyQt6.

---

## 📸 Скриншоты

![Скриншот интерфейса](screenshots.png)

---

## 🚀 Возможности

- Полная загрузка и парсинг существующего `~/.ssh/config`
- Создание, редактирование и удаление SSH-хостов
- Работа с группами хостов
- Поддержка глобальных настроек (`Host *`)
- Редактирование популярных SSH-параметров:
  - HostName
  - User
  - Port
  - IdentityFile (с выбором файла)
  - ProxyJump
  - Compression
  - StrictHostKeyChecking
  - ConnectTimeout
- Управление пробросами портов:
  - LocalForward
  - RemoteForward
  - DynamicForward
- Работа с дополнительными произвольными параметрами
- Автоматическое создание папки `.ssh` и файла `config`, если их нет
- Подсветка ошибок в параметрах (валидаторы)
- Поддержка поиска и фильтрации хостов
- Интуитивный drag-n-drop интерфейс (через QSplitter)

---

## 📦 Установка

1. Клонируйте репозиторий или скачайте скрипт:

```bash
git clone https://github.com/yourusername/ssh-config-editor.git
cd ssh-config-editor
```

2. Установите зависимости:

```bash
pip install -r requirements.txt
```

*Файл `requirements.txt` включает необходимые библиотеки.*

---

## ▶️ Запуск

Запустите скрипт:

```bash
python ssh_config.py
```

---

## 🛠 Требования

- Python 3.8+
- PyQt6
