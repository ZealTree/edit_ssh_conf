import os
import re
import shutil
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton,
    QHBoxLayout, QMessageBox, QInputDialog, QComboBox, QFormLayout,
    QSpinBox, QCheckBox, QTableWidget, QTableWidgetItem, QScrollArea,
    QSplitter, QFileDialog, QMenu
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QAction


class SSHConfigEditor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SSH Config Editor")
        self.setGeometry(100, 100, 800, 600)

        # Инициализация путей
        self.ssh_dir = Path.home() / ".ssh"
        self.ssh_config_path = self.ssh_dir / "config"
        self.profiles_dir = self.ssh_dir / "profiles"
        self.ensure_ssh_config_exists()

        self.hosts = {}  # {"группа": [{"name": "host1", "options": [...], "raw_options": [...]], ...]}
        self.global_options = []  # Для секции Host *
        self.current_host = None

        self.init_ui()
        self.load_config()

    def ensure_ssh_config_exists(self):
        """Обеспечивает существование директории .ssh и файла config с правильными правами."""
        self.ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.profiles_dir.mkdir(mode=0o700, exist_ok=True)
        if not self.ssh_config_path.exists():
            self.ssh_config_path.touch()
        os.chmod(self.ssh_config_path, 0o600)

    # Методы управления профилями
    def get_profiles(self):
        """Возвращает список имен сохраненных профилей."""
        return [f.stem for f in self.profiles_dir.glob("*.conf") if f.is_file()]

    def save_current_profile(self):
        """Сохраняет текущую конфигурацию как именованный профиль."""
        name, ok = QInputDialog.getText(
            self, "Сохранить профиль", "Введите имя профиля:"
        )
        if ok and name:
            if not re.match(r"^[\w\-]+$", name):
                QMessageBox.warning(self, "Ошибка", "Недопустимое имя профиля. Используйте только буквы, цифры и подчеркивания.")
                return
            
            profile_path = self.profiles_dir / f"{name}.conf"
            try:
                shutil.copy(self.ssh_config_path, profile_path)
                os.chmod(profile_path, 0o600)
                self.profile_combo.addItem(name)
                self.profile_combo.setCurrentText(name)
                QMessageBox.information(self, "Успех", f"Профиль '{name}' сохранен!")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить профиль: {str(e)}")

    def load_profile(self, name):
        """Загружает выбранный профиль."""
        if name == "Текущий":
            return

        profile_path = self.profiles_dir / f"{name}.conf"
        if not profile_path.exists():
            QMessageBox.warning(self, "Ошибка", "Профиль не существует!")
            return

        reply = QMessageBox.question(
            self, "Подтверждение загрузки",
            f"Загрузить профиль '{name}'? Текущая конфигурация будет перезаписана!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Создание резервной копии
                backup_path = self.ssh_config_path.with_suffix(".bak")
                shutil.copy(self.ssh_config_path, backup_path)
                
                # Замена конфигурации
                shutil.copy(profile_path, self.ssh_config_path)
                os.chmod(self.ssh_config_path, 0o600)
                
                self.load_config()
                QMessageBox.information(self, "Успех", f"Профиль '{name}' загружен! Резервная копия сохранена в {backup_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить профиль: {str(e)}")

    def delete_profile(self):
        """Удаляет выбранный профиль."""
        name = self.profile_combo.currentText()
        if name == "Текущий":
            return

        reply = QMessageBox.question(
            self, "Подтверждение удаления",
            f"Удалить профиль '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                (self.profiles_dir / f"{name}.conf").unlink()  # Исправлено: name вместо некорректного текста
                self.profile_combo.removeItem(self.profile_combo.currentIndex())
                QMessageBox.information(self, "Успех", f"Профиль '{name}' удален!")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось удалить профиль: {str(e)}")

    def init_ui(self):
        """Инициализирует пользовательский интерфейс."""
        # Основной макет с QSplitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Левая панель (дерево хостов и фильтры)
        left_panel = QVBoxLayout()

        # ComboBox для фильтрации групп
        self.group_filter = QComboBox()
        self.group_filter.addItem("Все")
        self.group_filter.addItem("Глобальные настройки")
        self.group_filter.currentTextChanged.connect(self.filter_by_group)
        left_panel.addWidget(self.group_filter)

        # Строка поиска
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск хостов...")
        self.search_edit.textChanged.connect(self.filter_hosts)
        left_panel.addWidget(self.search_edit)

        # Дерево хостов
        self.hosts_tree = QTreeWidget()
        self.hosts_tree.setHeaderHidden(True)
        self.hosts_tree.itemClicked.connect(self.on_host_selected)
        self.hosts_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)  # Включение контекстного меню
        self.hosts_tree.customContextMenuRequested.connect(self.show_context_menu)  # Подключение обработчика
        left_panel.addWidget(self.hosts_tree)

        # Кнопки "Добавить хост" и "Добавить группу"
        add_buttons_layout = QHBoxLayout()
        self.add_host_button = QPushButton("Добавить хост")
        self.add_host_button.clicked.connect(self.add_host)
        self.add_group_button = QPushButton("Добавить группу")
        self.add_group_button.clicked.connect(self.add_group)
        add_buttons_layout.addWidget(self.add_host_button)
        add_buttons_layout.addWidget(self.add_group_button)
        left_panel.addLayout(add_buttons_layout)

        left_widget = QWidget()
        left_widget.setLayout(left_panel)
        splitter.addWidget(left_widget)

        # Правая панель (детали хоста)
        right_panel = QVBoxLayout()

        # Элементы управления профилями
        profile_layout = QHBoxLayout()
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Текущий")
        self.profile_combo.addItems(self.get_profiles())
        profile_layout.addWidget(QLabel("Активный профиль:"))
        profile_layout.addWidget(self.profile_combo, 3)

        btn_load_profile = QPushButton("Загрузить")
        btn_load_profile.clicked.connect(lambda: self.load_profile(self.profile_combo.currentText()))
        profile_layout.addWidget(btn_load_profile)

        btn_save_profile = QPushButton("Сохранить как")
        btn_save_profile.clicked.connect(self.save_current_profile)
        profile_layout.addWidget(btn_save_profile)

        btn_delete_profile = QPushButton("Удалить")
        btn_delete_profile.clicked.connect(self.delete_profile)
        profile_layout.addWidget(btn_delete_profile)

        right_panel.addLayout(profile_layout)

        # Выбор группы
        self.group_label = QLabel("Группа:")
        self.group_edit = QLineEdit()
        self.group_edit.setPlaceholderText("Введите имя группы")
        right_panel.addWidget(self.group_label)
        right_panel.addWidget(self.group_edit)

        # Имя хоста
        self.host_label = QLabel("Имя хоста:")
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("Введите псевдоним хоста")
        right_panel.addWidget(self.host_label)
        right_panel.addWidget(self.host_edit)

        # Редактор опций
        self.options_label = QLabel("Опции:")
        right_panel.addWidget(self.options_label)

        # Область прокрутки для опций
        options_widget = QWidget()
        options_layout = QFormLayout()

        # Общие опции
        self.hostname_edit = QLineEdit()
        self.hostname_edit.setPlaceholderText("например, 127.0.0.1 или example.com")
        options_layout.addRow("HostName:", self.hostname_edit)

        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("например, root")
        options_layout.addRow("Пользователь:", self.user_edit)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        options_layout.addRow("Порт:", self.port_spin)

        # IdentityFile с кнопкой выбора файла
        identity_layout = QHBoxLayout()
        self.identity_file_edit = QLineEdit()
        self.identity_file_edit.setPlaceholderText("например, ~/.ssh/id_rsa")
        identity_layout.addWidget(self.identity_file_edit)
        self.identity_file_button = QPushButton("Обзор...")
        self.identity_file_button.clicked.connect(self.browse_identity_file)
        identity_layout.addWidget(self.identity_file_button)
        options_layout.addRow("IdentityFile:", identity_layout)

        # ProxyJump (редактируемый QComboBox)
        self.proxy_jump_combo = QComboBox()
        self.proxy_jump_combo.setEditable(True)
        self.proxy_jump_combo.addItem("")
        options_layout.addRow("ProxyJump:", self.proxy_jump_combo)

        self.compression_check = QCheckBox("Включить сжатие")
        options_layout.addRow("Сжатие:", self.compression_check)

        self.strict_host_check_combo = QComboBox()
        self.strict_host_check_combo.addItems(["", "yes", "no", "ask"])
        options_layout.addRow("StrictHostKeyChecking:", self.strict_host_check_combo)

        self.connect_timeout_spin = QSpinBox()
        self.connect_timeout_spin.setRange(0, 3600)
        self.connect_timeout_spin.setValue(0)
        options_layout.addRow("ConnectTimeout (секунды):", self.connect_timeout_spin)

        # Опции перенаправления
        self.local_forward_layout = QVBoxLayout()
        self.local_forward_button = QPushButton("Добавить LocalForward")
        self.local_forward_button.clicked.connect(self.add_local_forward)
        self.local_forward_layout.addWidget(self.local_forward_button)
        options_layout.addRow("LocalForward:", self.local_forward_layout)

        self.remote_forward_layout = QVBoxLayout()
        self.remote_forward_button = QPushButton("Добавить RemoteForward")
        self.remote_forward_button.clicked.connect(self.add_remote_forward)
        self.remote_forward_layout.addWidget(self.remote_forward_button)
        options_layout.addRow("RemoteForward:", self.remote_forward_layout)

        self.dynamic_forward_layout = QVBoxLayout()
        self.dynamic_forward_button = QPushButton("Добавить DynamicForward")
        self.dynamic_forward_button.clicked.connect(self.add_dynamic_forward)
        self.dynamic_forward_layout.addWidget(self.dynamic_forward_button)
        options_layout.addRow("DynamicForward:", self.dynamic_forward_layout)

        # Прочие опции (таблица для произвольных пар ключ-значение)
        self.other_options_table = QTableWidget()
        self.other_options_table.setColumnCount(2)
        self.other_options_table.setHorizontalHeaderLabels(["Ключ", "Значение"])
        self.other_options_table.setRowCount(0)
        self.other_options_table.setMinimumHeight(100)
        add_other_option_button = QPushButton("Добавить другую опцию")
        add_other_option_button.clicked.connect(self.add_other_option)
        options_layout.addRow("Другие опции:", self.other_options_table)
        options_layout.addRow("", add_other_option_button)

        options_widget.setLayout(options_layout)
        scroll_area = QScrollArea()
        scroll_area.setWidget(options_widget)
        scroll_area.setWidgetResizable(True)
        right_panel.addWidget(scroll_area, 2)

        # Кнопки
        buttons_layout = QHBoxLayout()
        self.save_button = QPushButton("Сохранить")
        self.save_button.clicked.connect(self.save_host)
        buttons_layout.addWidget(self.save_button)
        buttons_layout.addStretch()  # Растягивание для выравнивания
        right_panel.addLayout(buttons_layout)

        # Добавление правой панели в сплиттер
        right_widget = QWidget()
        right_widget.setLayout(right_panel)
        splitter.addWidget(right_widget)

        # Установка начальных размеров сплиттера
        splitter.setSizes([200, 600])

        # Установка главного виджета
        central_widget = QWidget()
        central_layout = QHBoxLayout()
        central_layout.addWidget(splitter)
        central_widget.setLayout(central_layout)
        self.setCentralWidget(central_widget)

        # Инициализация полей перенаправления
        self.local_forward_fields = []
        self.remote_forward_fields = []
        self.dynamic_forward_fields = []

    def browse_identity_file(self):
        """Открывает диалог выбора файла для IdentityFile."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл идентификации", str(Path.home() / ".ssh"), "Все файлы (*)"
        )
        if file_path:
            # Нормализация пути для кроссплатформенной совместимости
            file_path = str(Path(file_path))
            if file_path.startswith(str(Path.home())): 
                file_path = f"~/{Path(file_path).relative_to(Path.home())}"
            self.identity_file_edit.setText(file_path)

    def add_local_forward(self):
        """Добавляет поля для новой опции LocalForward."""
        forward_widget = QWidget()
        forward_layout = QHBoxLayout()
        local_port = QSpinBox()
        local_port.setRange(1, 65535)
        remote_host = QLineEdit()
        remote_host.setPlaceholderText("Удаленный хост")
        remote_port = QSpinBox()
        remote_port.setRange(1, 65535)
        remove_button = QPushButton("Удалить")
        remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.local_forward_fields))
        forward_layout.addWidget(local_port)
        forward_layout.addWidget(QLabel("к"))
        forward_layout.addWidget(remote_host)
        forward_layout.addWidget(QLabel(":"))
        forward_layout.addWidget(remote_port)
        forward_layout.addWidget(remove_button)
        forward_widget.setLayout(forward_layout)
        self.local_forward_layout.addWidget(forward_widget)
        self.local_forward_fields.append((forward_widget, local_port, remote_host, remote_port))

    def add_remote_forward(self):
        """Добавляет поля для новой опции RemoteForward."""
        forward_widget = QWidget()
        forward_layout = QHBoxLayout()
        remote_port = QSpinBox()
        remote_port.setRange(1, 65535)
        local_host = QLineEdit()
        local_host.setPlaceholderText("Локальный хост")
        local_port = QSpinBox()
        local_port.setRange(1, 65535)
        remove_button = QPushButton("Удалить")
        remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.remote_forward_fields))
        forward_layout.addWidget(remote_port)
        forward_layout.addWidget(QLabel("к"))
        forward_layout.addWidget(local_host)
        forward_layout.addWidget(QLabel(":"))
        forward_layout.addWidget(local_port)
        forward_layout.addWidget(remove_button)
        forward_widget.setLayout(forward_layout)
        self.remote_forward_layout.addWidget(forward_widget)
        self.remote_forward_fields.append((forward_widget, remote_port, local_host, local_port))

    def add_dynamic_forward(self):
        """Добавляет поля для новой опции DynamicForward."""
        forward_widget = QWidget()
        forward_layout = QHBoxLayout()
        port = QSpinBox()
        port.setRange(1, 65535)
        remove_button = QPushButton("Удалить")
        remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.dynamic_forward_fields))
        forward_layout.addWidget(QLabel("Порт:"))
        forward_layout.addWidget(port)
        forward_layout.addWidget(remove_button)
        forward_widget.setLayout(forward_layout)
        self.dynamic_forward_layout.addWidget(forward_widget)
        self.dynamic_forward_fields.append((forward_widget, port))

    def remove_forward(self, widget, fields_list):
        """Удаляет поле перенаправления."""
        widget.deleteLater()
        for i, field in enumerate(fields_list):
            if field[0] == widget:
                fields_list.pop(i)
                break

    def add_other_option(self):
        """Добавляет строку в таблицу других опций."""
        row = self.other_options_table.rowCount()
        self.other_options_table.insertRow(row)
        self.other_options_table.setItem(row, 0, QTableWidgetItem(""))
        self.other_options_table.setItem(row, 1, QTableWidgetItem(""))

    def is_valid_hostname(self, hostname):
        """Проверяет, является ли hostname действительным IP или доменным именем."""
        if not hostname:
            return False
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        domain_pattern = r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$"
        return bool(re.match(ip_pattern, hostname) or re.match(domain_pattern, hostname))

    def validate_option(self, key, value):
        """Проверяет формат опции SSH."""
        if not value or not key:
            return True, ""
        key = key.lower()
        if key == "port":
            if not value.isdigit() or not (1 <= int(value) <= 65535):
                return False, "Порт должен быть числом от 1 до 65535"
        elif key == "hostname" and not self.is_valid_hostname(value):
            return False, "Недопустимый HostName (должен быть IP или домен)"
        elif key == "proxyjump":
            return True, ""
        elif key in ("localforward", "remoteforward"):
            parts = value.split()
            if len(parts) != 2 or not parts[0].isdigit() or not (1 <= int(parts[0]) <= 65535):
                return False, f"{key} должен быть в формате 'локальный_порт удаленный_хост:удаленный_порт'"
            remote_host_port = parts[1].split(":")
            if len(remote_host_port) != 2 or not remote_host_port[1].isdigit() or not (1 <= int(remote_host_port[1]) <= 65535):
                return False, f"{key} удаленный хост должен быть в формате 'хост:порт'"
            if not self.is_valid_hostname(remote_host_port[0]):
                return False, f"{key} удаленный хост должен быть действительным IP или доменом"
        elif key == "dynamicforward":
            if not value.isdigit() or not (1 <= int(value) <= 65535):
                return False, "DynamicForward должен быть номером порта от 1 до 65535"
        elif key == "connecttimeout":
            if not value.isdigit() or int(value) < 0:
                return False, "ConnectTimeout должен быть неотрицательным числом"
        elif key == "stricthostkeychecking":
            if value not in ("yes", "no", "ask"):
                return False, "StrictHostKeyChecking должен быть 'yes', 'no' или 'ask'"
        return True, ""

    def load_config(self):
        """Парсит файл конфигурации SSH и заполняет список хостов."""
        self.hosts = {}
        self.global_options = []
        current_group = "По умолчанию"
        current_host = None
        in_global_section = False

        try:
            with open(self.ssh_config_path, "r") as f:
                lines = f.readlines()

            i = 0
            while i < len(lines):
                line = lines[i]
                stripped_line = line.strip()

                # Проверка трехстрочного заголовка группы
                if (
                    i + 2 < len(lines) and
                    stripped_line.startswith("##") and
                    lines[i + 1].strip().startswith("#") and
                    lines[i + 2].strip().startswith("##")
                ):
                    current_group = lines[i + 1].strip().lstrip("#").strip() or "Безымянная группа"
                    if current_group not in self.hosts:
                        self.hosts[current_group] = []
                    i += 3
                    continue

                # Обнаружение однострочных заголовков групп
                if stripped_line.startswith("##") and not stripped_line[2:].strip():
                    current_group = stripped_line.strip("#").strip() or "Безымянная группа"
                    if current_group not in self.hosts:
                        self.hosts[current_group] = []
                    i += 1
                    continue

                # Пропуск пустых строк и нерелевантных комментариев
                if not stripped_line or (stripped_line.startswith("#") and not stripped_line[1:].strip()):
                    i += 1
                    continue

                # Обнаружение директивы Host
                if line.lower().lstrip().startswith("host "):
                    parts = line.split()
                    host_names = [name.strip() for name in parts[1:]]
                    if host_names == ["*"]:
                        in_global_section = True
                        self.global_options = []
                        current_host = None
                    else:
                        in_global_section = False
                        for host_name in host_names:
                            current_host = {"name": host_name, "options": [], "raw_options": []}
                            if current_group not in self.hosts:
                                self.hosts[current_group] = []
                            self.hosts[current_group].append(current_host)
                    i += 1
                    continue

                # Добавление опций
                if in_global_section and line.strip():
                    self.global_options.append(line.strip())
                elif current_host and line.rstrip():
                    current_host["options"].append(line.strip())
                    current_host["raw_options"].append(line.strip())
                i += 1

            self.update_hosts_tree()
            self.update_group_filter()
            self.update_proxy_jump_options()

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось разобрать конфигурацию: {str(e)}")

    def update_hosts_tree(self):
        """Обновляет QTreeWidget с хостами, сгруппированными по секциям."""
        self.hosts_tree.clear()
        selected_group = self.group_filter.currentText()

        if self.global_options and (selected_group == "Все" or selected_group == "Глобальные настройки"):
            global_item = QTreeWidgetItem(self.hosts_tree, ["Глобальные настройки"])
            global_item.setForeground(0, QColor(0, 0, 255))
            global_item.setBackground(0, QColor(240, 240, 240))
            global_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            host_item = QTreeWidgetItem(global_item, ["Host *"])
            host_item.setData(0, Qt.ItemDataRole.UserRole, ("Глобальные", "*"))
            global_item.setExpanded(True)

        for group, hosts in self.hosts.items():
            if selected_group != "Все" and selected_group != group:
                continue
            group_item = QTreeWidgetItem(self.hosts_tree, [group])
            group_item.setForeground(0, QColor(0, 0, 255))
            group_item.setBackground(0, QColor(240, 240, 240))
            group_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            for host in hosts:
                search_text = self.search_edit.text().lower()
                if not search_text or search_text in host["name"].lower() or any(search_text in opt.lower() for opt in host["options"]):
                    host_item = QTreeWidgetItem(group_item, [host["name"]])
                    host_item.setData(0, Qt.ItemDataRole.UserRole, (group, host["name"]))
            group_item.setExpanded(True)

    def update_group_filter(self):
        """Обновляет QComboBox с доступными группами."""
        current = self.group_filter.currentText()
        self.group_filter.clear()
        self.group_filter.addItem("Все")
        self.group_filter.addItem("Глобальные настройки")
        for group in sorted(self.hosts.keys()):
            self.group_filter.addItem(group)
        index = self.group_filter.findText(current)
        if index >= 0:
            self.group_filter.setCurrentIndex(index)
        else:
            self.group_filter.setCurrentIndex(0)

    def update_proxy_jump_options(self):
        """Обновляет QComboBox ProxyJump с доступными хостами."""
        current = self.proxy_jump_combo.currentText()
        self.proxy_jump_combo.clear()
        self.proxy_jump_combo.addItem("")
        added_hosts = set()
        for group, hosts in self.hosts.items():
            for host in hosts:
                host_name = host["name"]
                if host_name not in added_hosts:
                    self.proxy_jump_combo.addItem(host_name)
                    added_hosts.add(host_name)
        index = self.proxy_jump_combo.findText(current)
        if index >= 0:
            self.proxy_jump_combo.setCurrentIndex(index)
        else:
            self.proxy_jump_combo.setCurrentText(current)

    def filter_by_group(self, group):
        """Фильтрует дерево по выбранной группе."""
        self.update_hosts_tree()

    def filter_hosts(self, text):
        """Фильтрует хосты по тексту поиска."""
        self.update_hosts_tree()

    def show_context_menu(self, position):
        """Показывает контекстное меню для выбранного элемента в Hosts Tree."""
        item = self.hosts_tree.itemAt(position)
        if not item:
            return

        menu = QMenu(self)
        data = item.data(0, Qt.ItemDataRole.UserRole)

        if data:  # Это хост
            group, host_name = data
            if host_name == "*":  # Глобальные настройки
                return  # Не показываем меню для Host *
            
            # Меню для хоста
            rename_host_action = QAction("Переименовать хост", self)
            rename_host_action.triggered.connect(lambda: self.rename_host(group, host_name))
            delete_host_action = QAction("Удалить хост", self)
            delete_host_action.triggered.connect(self.delete_host)
            menu.addAction(rename_host_action)
            menu.addAction(delete_host_action)
        else:  # Это группа
            group_name = item.text(0)
            if group_name == "Глобальные настройки":
                return  # Не показываем меню для глобальных настроек
            
            # Меню для группы
            rename_group_action = QAction("Переименовать группу", self)
            rename_group_action.triggered.connect(lambda: self.rename_group(group_name))
            delete_group_action = QAction("Удалить группу", self)
            delete_group_action.triggered.connect(lambda: self.delete_group(group_name))
            menu.addAction(rename_group_action)
            menu.addAction(delete_group_action)

        menu.exec(self.hosts_tree.mapToGlobal(position))

    def on_host_selected(self, item, column):
        """Загружает детали хоста при клике."""
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return

        group, host_name = data
        self.current_host = (group, host_name)

        # Очистка предыдущих полей перенаправления
        for widget, _, _, _ in self.local_forward_fields + self.remote_forward_fields:
            widget.deleteLater()
        for widget, _ in self.dynamic_forward_fields:
            widget.deleteLater()
        self.local_forward_fields = []
        self.remote_forward_fields = []
        self.dynamic_forward_fields = []
        self.other_options_table.setRowCount(0)

        if group == "Глобальные" and host_name == "*":
            self.group_edit.setText("Глобальные")
            self.host_edit.setText("*")
            self.load_options_to_fields(self.global_options)
            return

        host_data = None
        for host in self.hosts[group]:
            if host["name"] == host_name:
                host_data = host
                break

        if host_data:
            self.group_edit.setText(group)
            self.host_edit.setText(host_name)
            self.load_options_to_fields(host_data["raw_options"])

    def load_options_to_fields(self, options):
        """Загружает опции в поля интерфейса."""
        self.hostname_edit.clear()
        self.user_edit.clear()
        self.port_spin.setValue(22)
        self.identity_file_edit.clear()
        self.proxy_jump_combo.setCurrentText("")
        self.compression_check.setChecked(False)
        self.strict_host_check_combo.setCurrentText("")
        self.connect_timeout_spin.setValue(0)

        for option in options:
            option = option.strip()
            if not option:
                continue
            parts = option.split(maxsplit=1)
            if len(parts) < 2:
                continue
            key, value = parts
            key_lower = key.lower()
            if key_lower == "hostname":
                self.hostname_edit.setText(value)
            elif key_lower == "user":
                self.user_edit.setText(value)
            elif key_lower == "port":
                try:
                    self.port_spin.setValue(int(value))
                except ValueError:
                    pass
            elif key_lower == "identityfile":
                self.identity_file_edit.setText(value)
            elif key_lower == "proxyjump":
                self.proxy_jump_combo.setCurrentText(value)
            elif key_lower == "compression":
                self.compression_check.setChecked(value.lower() == "yes")
            elif key_lower == "stricthostkeychecking":
                self.strict_host_check_combo.setCurrentText(value)
            elif key_lower == "connecttimeout":
                try:
                    self.connect_timeout_spin.setValue(int(value))
                except ValueError:
                    pass
            elif key_lower == "localforward":
                local_port, remote_host_port = value.split(maxsplit=1)
                remote_host, remote_port = remote_host_port.split(":")
                forward_widget = QWidget()
                forward_layout = QHBoxLayout()
                lp = QSpinBox()
                lp.setRange(1, 65535)
                lp.setValue(int(local_port))
                rh = QLineEdit()
                rh.setText(remote_host)
                rp = QSpinBox()
                rp.setRange(1, 65535)
                rp.setValue(int(remote_port))
                remove_button = QPushButton("Удалить")
                remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.local_forward_fields))
                forward_layout.addWidget(lp)
                forward_layout.addWidget(QLabel("к"))
                forward_layout.addWidget(rh)
                forward_layout.addWidget(QLabel(":"))
                forward_layout.addWidget(rp)
                forward_layout.addWidget(remove_button)
                forward_widget.setLayout(forward_layout)
                self.local_forward_layout.addWidget(forward_widget)
                self.local_forward_fields.append((forward_widget, lp, rh, rp))
            elif key_lower == "remoteforward":
                remote_port, local_host_port = value.split(maxsplit=1)
                local_host, local_port = local_host_port.split(":")
                forward_widget = QWidget()
                forward_layout = QHBoxLayout()
                rp = QSpinBox()
                rp.setRange(1, 65535)
                rp.setValue(int(remote_port))
                lh = QLineEdit()
                lh.setText(local_host)
                lp = QSpinBox()
                lp.setRange(1, 65535)
                lp.setValue(int(local_port))
                remove_button = QPushButton("Удалить")
                remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.remote_forward_fields))
                forward_layout.addWidget(rp)
                forward_layout.addWidget(QLabel("к"))
                forward_layout.addWidget(lh)
                forward_layout.addWidget(QLabel(":"))
                forward_layout.addWidget(lp)
                forward_layout.addWidget(remove_button)
                forward_widget.setLayout(forward_layout)
                self.remote_forward_layout.addWidget(forward_widget)
                self.remote_forward_fields.append((forward_widget, rp, lh, lp))
            elif key_lower == "dynamicforward":
                forward_widget = QWidget()
                forward_layout = QHBoxLayout()
                port = QSpinBox()
                port.setRange(1, 65535)
                port.setValue(int(value))
                remove_button = QPushButton("Удалить")
                remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.dynamic_forward_fields))
                forward_layout.addWidget(QLabel("Порт:"))
                forward_layout.addWidget(port)
                forward_layout.addWidget(remove_button)
                forward_widget.setLayout(forward_layout)
                self.dynamic_forward_layout.addWidget(forward_widget)
                self.dynamic_forward_fields.append((forward_widget, port))
            else:
                row = self.other_options_table.rowCount()
                self.other_options_table.insertRow(row)
                self.other_options_table.setItem(row, 0, QTableWidgetItem(key))
                self.other_options_table.setItem(row, 1, QTableWidgetItem(value))

    def is_host_unique(self, group, name, old_group=None, old_name=None):
        """Проверяет уникальность имени хоста, исключая старое имя при обновлении."""
        for g, hosts in self.hosts.items():
            if g == old_group and name == old_name:
                continue
            for host in hosts:
                if host["name"] == name:
                    return False
        return True

    def save_host(self):
        """Сохраняет изменения текущего хоста."""
        if not self.current_host:
            QMessageBox.warning(self, "Предупреждение", "Хост не выбран")
            return

        old_group, old_name = self.current_host
        new_group = self.group_edit.text().strip() or "По умолчанию"
        new_name = self.host_edit.text().strip()
        new_options = []
        new_raw_options = []

        if not new_name:
            QMessageBox.warning(self, "Предупреждение", "Имя хоста не может быть пустым")
            return

        # Сбор опций из полей
        if self.hostname_edit.text().strip():
            new_options.append(f"HostName {self.hostname_edit.text().strip()}")
            new_raw_options.append(f"\tHostName {self.hostname_edit.text().strip()}")
        if self.user_edit.text().strip():
            new_options.append(f"User {self.user_edit.text().strip()}")
            new_raw_options.append(f"\tUser {self.user_edit.text().strip()}")
        if self.port_spin.value() != 22:
            new_options.append(f"Port {self.port_spin.value()}")
            new_raw_options.append(f"\tPort {self.port_spin.value()}")
        if self.identity_file_edit.text().strip():
            new_options.append(f"IdentityFile {self.identity_file_edit.text().strip()}")
            new_raw_options.append(f"\tIdentityFile {self.identity_file_edit.text().strip()}")
        if self.proxy_jump_combo.currentText():
            new_options.append(f"ProxyJump {self.proxy_jump_combo.currentText()}")
            new_raw_options.append(f"\tProxyJump {self.proxy_jump_combo.currentText()}")
        if self.compression_check.isChecked():
            new_options.append("Compression yes")
            new_raw_options.append("\tCompression yes")
        if self.strict_host_check_combo.currentText():
            new_options.append(f"StrictHostKeyChecking {self.strict_host_check_combo.currentText()}")
            new_raw_options.append(f"\tStrictHostKeyChecking {self.strict_host_check_combo.currentText()}")
        if self.connect_timeout_spin.value() > 0:
            new_options.append(f"ConnectTimeout {self.connect_timeout_spin.value()}")
            new_raw_options.append(f"\tConnectTimeout {self.connect_timeout_spin.value()}")

        # LocalForward
        for _, local_port, remote_host, remote_port in self.local_forward_fields:
            if local_port.value() and remote_host.text().strip() and remote_port.value():
                value = f"{local_port.value()} {remote_host.text().strip()}:{remote_port.value()}"
                new_options.append(f"LocalForward {value}")
                new_raw_options.append(f"\tLocalForward {value}")

        # RemoteForward
        for _, remote_port, local_host, local_port in self.remote_forward_fields:
            if remote_port.value() and local_host.text().strip() and local_port.value():
                value = f"{remote_port.value()} {local_host.text().strip()}:{local_port.value()}"
                new_options.append(f"RemoteForward {value}")
                new_raw_options.append(f"\tRemoteForward {value}")

        # DynamicForward
        for _, port in self.dynamic_forward_fields:
            if port.value():
                value = f"{port.value()}"
                new_options.append(f"DynamicForward {value}")
                new_raw_options.append(f"\tDynamicForward {value}")

        # Прочие опции
        for row in range(self.other_options_table.rowCount()):
            key_item = self.other_options_table.item(row, 0)
            value_item = self.other_options_table.item(row, 1)
            key = key_item.text().strip() if key_item else ""
            value = value_item.text().strip() if value_item else ""
            if key and value:
                new_options.append(f"{key} {value}")
                new_raw_options.append(f"\t{key} {value}")

        # Валидация опций
        for option in new_options:
            parts = option.split(maxsplit=1)
            key = parts[0]
            value = parts[1] if len(parts) > 1 else ""
            valid, error = self.validate_option(key, value)
            if not valid:
                QMessageBox.warning(self, "Недопустимая опция", error)
                return

        # Проверка уникальности хоста
        if not self.is_host_unique(new_group, new_name, old_group, old_name):
            QMessageBox.warning(self, "Предупреждение", f"Хост '{new_name}' уже существует")
            return

        if old_name == "*":
            self.global_options = new_raw_options
            self.update_hosts_tree()
            self.update_group_filter()
            self.update_proxy_jump_options()
            self.save_config()
            return

        # Поиск и обновление хоста
        found = False
        for group in list(self.hosts.keys()):
            for i, host in enumerate(self.hosts[group]):
                if host["name"] == old_name and group == old_group:
                    self.hosts[group].pop(i)
                    if new_group not in self.hosts:
                        self.hosts[new_group] = []
                    self.hosts[new_group].append({
                        "name": new_name,
                        "options": new_options,
                        "raw_options": new_raw_options
                    })
                    self.current_host = (new_group, new_name)
                    found = True
                    break
            if found:
                break

        if not found:
            if new_group not in self.hosts:
                self.hosts[new_group] = []
            self.hosts[new_group].append({
                "name": new_name,
                "options": new_options,
                "raw_options": new_raw_options
            })
            self.current_host = (new_group, new_name)

        self.update_hosts_tree()
        self.update_group_filter()
        self.update_proxy_jump_options()
        self.save_config()

    def delete_host(self):
        """Удаляет текущий хост."""
        if not self.current_host:
            QMessageBox.warning(self, "Предупреждение", "Хост не выбран")
            return

        group, name = self.current_host
        reply = QMessageBox.question(
            self, "Подтверждение удаления",
            f"Вы уверены, что хотите удалить хост '{name}' из группы '{group}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            if name == "*":
                self.global_options = []
            else:
                self.hosts[group] = [h for h in self.hosts[group] if h["name"] != name]
                if not self.hosts[group]:
                    del self.hosts[group]
            
            self.current_host = None
            self.group_edit.clear()
            self.host_edit.clear()
            self.clear_options_fields()
            
            self.update_hosts_tree()
            self.update_group_filter()
            self.update_proxy_jump_options()
            self.save_config()

    def rename_host(self, group, old_name):
        """Переименовывает хост."""
        new_name, ok = QInputDialog.getText(
            self, "Переименовать хост", "Введите новое имя хоста:",
            QLineEdit.EchoMode.Normal, old_name
        )
        if ok and new_name.strip() and new_name != old_name:
            if not self.is_host_unique(group, new_name, group, old_name):
                QMessageBox.warning(self, "Ошибка", f"Хост '{new_name}' уже существует")
                return
            for host in self.hosts[group]:
                if host["name"] == old_name:
                    host["name"] = new_name
                    break
            self.current_host = (group, new_name)
            self.host_edit.setText(new_name)
            self.update_hosts_tree()
            self.update_proxy_jump_options()
            self.save_config()

    def clear_options_fields(self):
        """Очищает все поля опций."""
        self.hostname_edit.clear()
        self.user_edit.clear()
        self.port_spin.setValue(22)
        self.identity_file_edit.clear()
        self.proxy_jump_combo.setCurrentText("")
        self.compression_check.setChecked(False)
        self.strict_host_check_combo.setCurrentText("")
        self.connect_timeout_spin.setValue(0)
        for widget, _, _, _ in self.local_forward_fields + self.remote_forward_fields:
            widget.deleteLater()
        for widget, _ in self.dynamic_forward_fields:
            widget.deleteLater()
        self.local_forward_fields = []
        self.remote_forward_fields = []
        self.dynamic_forward_fields = []
        self.other_options_table.setRowCount(0)

    def add_host(self):
        """Добавляет новый хост."""
        if not self.hosts:
            self.hosts["По умолчанию"] = []

        group, ok = QInputDialog.getItem(
            self, "Добавить хост", "Выберите группу:",
            list(self.hosts.keys()), 0, False
        )
        if not ok:
            return

        name, ok = QInputDialog.getText(
            self, "Добавить хост", "Введите имя хоста:",
            QLineEdit.EchoMode.Normal
        )
        if not ok or not name.strip():
            return

        name = name.strip()
        if not self.is_host_unique(group, name):
            QMessageBox.warning(self, "Предупреждение", f"Хост '{name}' уже существует")
            return

        if group not in self.hosts:
            self.hosts[group] = []
        
        self.hosts[group].append({
            "name": name,
            "options": [f"HostName {name}"],
            "raw_options": [f"\tHostName {name}"]
        })

        self.update_hosts_tree()
        self.update_group_filter()
        self.update_proxy_jump_options()
        self.save_config()

    def add_group(self):
        """Добавляет новую группу."""
        group_name, ok = QInputDialog.getText(
            self, "Добавить группу", "Введите имя группы:",
            QLineEdit.EchoMode.Normal
        )
        if ok and group_name.strip():
            if group_name.strip() not in self.hosts:
                self.hosts[group_name.strip()] = []
                self.update_hosts_tree()
                self.update_group_filter()

    def rename_group(self, old_group):
        """Переименовывает группу."""
        new_group, ok = QInputDialog.getText(
            self, "Переименовать группу", "Введите новое имя группы:",
            QLineEdit.EchoMode.Normal, old_group
        )
        if ok and new_group.strip() and new_group.strip() not in self.hosts:
            self.hosts[new_group.strip()] = self.hosts.pop(old_group)
            if self.current_host and self.current_host[0] == old_group:
                self.current_host = (new_group.strip(), self.current_host[1])
            self.group_edit.setText(new_group.strip())
            self.update_hosts_tree()
            self.update_group_filter()
            self.save_config()

    def delete_group(self, group_name):
        """Удаляет группу."""
        if not self.hosts[group_name]:
            reply = QMessageBox.question(
                self, "Подтверждение удаления",
                f"Вы уверены, что хотите удалить группу '{group_name}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
        else:
            reply = QMessageBox.question(
                self, "Подтверждение удаления",
                f"Группа '{group_name}' содержит хосты. Удалить группу и все её хосты?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
        if reply == QMessageBox.StandardButton.Yes:
            del self.hosts[group_name]
            if self.current_host and self.current_host[0] == group_name:
                self.current_host = None
                self.group_edit.clear()
                self.host_edit.clear()
                self.clear_options_fields()
            self.update_hosts_tree()
            self.update_group_filter()
            self.update_proxy_jump_options()
            self.save_config()

    def save_config(self):
        """Сохраняет текущую конфигурацию в файл SSH config."""
        try:
            with open(self.ssh_config_path, "w") as f:
                if self.global_options:
                    f.write("Host *\n")
                    for option in self.global_options:
                        f.write(f"{option}\n")
                    f.write("\n")

                for group, hosts in self.hosts.items():
                    if not hosts:
                        continue
                    
                    f.write("#############################################\n")
                    f.write(f"# {group}\n")
                    f.write("#############################################\n\n")
                    
                    for host in hosts:
                        f.write(f"Host {host['name']}\n")
                        for option in host['raw_options']:
                            f.write(f"{option}\n")
                        f.write("\n")
            
            os.chmod(self.ssh_config_path, 0o600)
            QMessageBox.information(self, "Успех", "Конфигурация SSH успешно сохранена!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить конфигурацию: {str(e)}")


if __name__ == "__main__":
    app = QApplication([])
    editor = SSHConfigEditor()
    editor.show()
    app.exec()