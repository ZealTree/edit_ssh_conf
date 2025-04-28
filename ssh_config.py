import os
import re
import shutil
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton,
    QHBoxLayout, QMessageBox, QInputDialog, QComboBox, QFormLayout,
    QSpinBox, QCheckBox, QTableWidget, QTableWidgetItem, QScrollArea,
    QSplitter, QFileDialog
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor


class SSHConfigEditor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SSH Config Editor")
        self.setGeometry(100, 100, 800, 600)

        # Initialize paths
        self.ssh_dir = Path.home() / ".ssh"
        self.ssh_config_path = self.ssh_dir / "config"
        self.profiles_dir = self.ssh_dir / "profiles"
        self.ensure_ssh_config_exists()

        self.hosts = {}  # {"group": [{"name": "host1", "options": [...], "raw_options": [...]], ...]}
        self.global_options = []  # For Host * section
        self.current_host = None

        self.init_ui()
        self.load_config()

    def ensure_ssh_config_exists(self):
        """Ensure .ssh directory and config file exist with proper permissions."""
        self.ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.profiles_dir.mkdir(mode=0o700, exist_ok=True)
        if not self.ssh_config_path.exists():
            self.ssh_config_path.touch()
        os.chmod(self.ssh_config_path, 0o600)

    # Profile management methods
    def get_profiles(self):
        """Return list of saved profile names."""
        return [f.stem for f in self.profiles_dir.glob("*.conf") if f.is_file()]

    def save_current_profile(self):
        """Save current config as a named profile."""
        name, ok = QInputDialog.getText(
            self, "Save Profile", "Enter profile name:"
        )
        if ok and name:
            if not re.match(r"^[\w\-]+$", name):
                QMessageBox.warning(self, "Error", "Invalid profile name. Use only letters, numbers and underscores.")
                return
            
            profile_path = self.profiles_dir / f"{name}.conf"
            try:
                shutil.copy(self.ssh_config_path, profile_path)
                os.chmod(profile_path, 0o600)
                self.profile_combo.addItem(name)
                self.profile_combo.setCurrentText(name)
                QMessageBox.information(self, "Success", f"Profile '{name}' saved!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save profile: {str(e)}")

    def load_profile(self, name):
        """Load selected profile."""
        if name == "Current":
            return

        profile_path = self.profiles_dir / f"{name}.conf"
        if not profile_path.exists():
            QMessageBox.warning(self, "Error", "Profile does not exist!")
            return

        reply = QMessageBox.question(
            self, "Confirm Load",
            f"Load profile '{name}'? Current configuration will be overwritten!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Create backup
                backup_path = self.ssh_config_path.with_suffix(".bak")
                shutil.copy(self.ssh_config_path, backup_path)
                
                # Replace config
                shutil.copy(profile_path, self.ssh_config_path)
                os.chmod(self.ssh_config_path, 0o600)
                
                self.load_config()
                QMessageBox.information(self, "Success", f"Profile '{name}' loaded! Backup saved to {backup_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load profile: {str(e)}")

    def delete_profile(self):
        """Delete selected profile."""
        name = self.profile_combo.currentText()
        if name == "Current":
            return

        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Delete profile '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                (self.profiles_dir / f"{name}.conf").unlink()
                self.profile_combo.removeItem(self.profile_combo.currentIndex())
                QMessageBox.information(self, "Success", f"Profile '{name}' deleted!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete profile: {str(e)}")

    def init_ui(self):
        """Initialize the user interface."""
        # Main layout with QSplitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel (Hosts tree and filters)
        left_panel = QVBoxLayout()

        # ComboBox for group filtering
        self.group_filter = QComboBox()
        self.group_filter.addItem("All")
        self.group_filter.addItem("Global Settings")
        self.group_filter.currentTextChanged.connect(self.filter_by_group)
        left_panel.addWidget(self.group_filter)

        # Search bar
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search hosts...")
        self.search_edit.textChanged.connect(self.filter_hosts)
        left_panel.addWidget(self.search_edit)

        # Tree widget for hosts
        self.hosts_tree = QTreeWidget()
        self.hosts_tree.setHeaderHidden(True)
        self.hosts_tree.itemClicked.connect(self.on_host_selected)
        left_panel.addWidget(self.hosts_tree)

        left_widget = QWidget()
        left_widget.setLayout(left_panel)
        splitter.addWidget(left_widget)

        # Right panel (Host details)
        right_panel = QVBoxLayout()

        # Profile management controls
        profile_layout = QHBoxLayout()
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Current")
        self.profile_combo.addItems(self.get_profiles())
        profile_layout.addWidget(QLabel("Active Profile:"))
        profile_layout.addWidget(self.profile_combo, 3)

        btn_load_profile = QPushButton("Load")
        btn_load_profile.clicked.connect(lambda: self.load_profile(self.profile_combo.currentText()))
        profile_layout.addWidget(btn_load_profile)

        btn_save_profile = QPushButton("Save As")
        btn_save_profile.clicked.connect(self.save_current_profile)
        profile_layout.addWidget(btn_save_profile)

        btn_delete_profile = QPushButton("Delete")
        btn_delete_profile.clicked.connect(self.delete_profile)
        profile_layout.addWidget(btn_delete_profile)

        right_panel.addLayout(profile_layout)

        # Group selection
        self.group_label = QLabel("Group:")
        self.group_edit = QLineEdit()
        self.group_edit.setPlaceholderText("Enter group name")
        right_panel.addWidget(self.group_label)
        right_panel.addWidget(self.group_edit)

        # Host name
        self.host_label = QLabel("Host Name:")
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("Enter host alias")
        right_panel.addWidget(self.host_label)
        right_panel.addWidget(self.host_edit)

        # Options editor
        self.options_label = QLabel("Options:")
        right_panel.addWidget(self.options_label)

        # Scroll area for options
        options_widget = QWidget()
        options_layout = QFormLayout()

        # Common options
        self.hostname_edit = QLineEdit()
        self.hostname_edit.setPlaceholderText("e.g., 127.0.0.1 or example.com")
        options_layout.addRow("HostName:", self.hostname_edit)

        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("e.g., root")
        options_layout.addRow("User:", self.user_edit)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        options_layout.addRow("Port:", self.port_spin)

        # IdentityFile with a button to select file
        identity_layout = QHBoxLayout()
        self.identity_file_edit = QLineEdit()
        self.identity_file_edit.setPlaceholderText("e.g., ~/.ssh/id_rsa")
        identity_layout.addWidget(self.identity_file_edit)
        self.identity_file_button = QPushButton("Browse...")
        self.identity_file_button.clicked.connect(self.browse_identity_file)
        identity_layout.addWidget(self.identity_file_button)
        options_layout.addRow("IdentityFile:", identity_layout)

        # ProxyJump (editable QComboBox)
        self.proxy_jump_combo = QComboBox()
        self.proxy_jump_combo.setEditable(True)
        self.proxy_jump_combo.addItem("")
        options_layout.addRow("ProxyJump:", self.proxy_jump_combo)

        self.compression_check = QCheckBox("Enable Compression")
        options_layout.addRow("Compression:", self.compression_check)

        self.strict_host_check_combo = QComboBox()
        self.strict_host_check_combo.addItems(["", "yes", "no", "ask"])
        options_layout.addRow("StrictHostKeyChecking:", self.strict_host_check_combo)

        self.connect_timeout_spin = QSpinBox()
        self.connect_timeout_spin.setRange(0, 3600)
        self.connect_timeout_spin.setValue(0)
        options_layout.addRow("ConnectTimeout (seconds):", self.connect_timeout_spin)

        # Forwarding options
        self.local_forward_layout = QVBoxLayout()
        self.local_forward_button = QPushButton("Add LocalForward")
        self.local_forward_button.clicked.connect(self.add_local_forward)
        self.local_forward_layout.addWidget(self.local_forward_button)
        options_layout.addRow("LocalForward:", self.local_forward_layout)

        self.remote_forward_layout = QVBoxLayout()
        self.remote_forward_button = QPushButton("Add RemoteForward")
        self.remote_forward_button.clicked.connect(self.add_remote_forward)
        self.remote_forward_layout.addWidget(self.remote_forward_button)
        options_layout.addRow("RemoteForward:", self.remote_forward_layout)

        # DynamicForward
        self.dynamic_forward_layout = QVBoxLayout()
        self.dynamic_forward_button = QPushButton("Add DynamicForward")
        self.dynamic_forward_button.clicked.connect(self.add_dynamic_forward)
        self.dynamic_forward_layout.addWidget(self.dynamic_forward_button)
        options_layout.addRow("DynamicForward:", self.dynamic_forward_layout)

        # Other options (table for arbitrary key-value pairs)
        self.other_options_table = QTableWidget()
        self.other_options_table.setColumnCount(2)
        self.other_options_table.setHorizontalHeaderLabels(["Key", "Value"])
        self.other_options_table.setRowCount(0)
        self.other_options_table.setMinimumHeight(100)
        add_other_option_button = QPushButton("Add Other Option")
        add_other_option_button.clicked.connect(self.add_other_option)
        options_layout.addRow("Other Options:", self.other_options_table)
        options_layout.addRow("", add_other_option_button)

        options_widget.setLayout(options_layout)
        scroll_area = QScrollArea()
        scroll_area.setWidget(options_widget)
        scroll_area.setWidgetResizable(True)
        right_panel.addWidget(scroll_area, 2)

        # Buttons
        buttons_layout = QHBoxLayout()
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_host)
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_host)
        self.add_button = QPushButton("Add Host")
        self.add_button.clicked.connect(self.add_host)
        self.add_group_button = QPushButton("Add Group")
        self.add_group_button.clicked.connect(self.add_group)
        self.rename_group_button = QPushButton("Rename Group")
        self.rename_group_button.clicked.connect(self.rename_group)
        buttons_layout.addWidget(self.save_button)
        buttons_layout.addWidget(self.delete_button)
        buttons_layout.addWidget(self.add_button)
        buttons_layout.addWidget(self.add_group_button)
        buttons_layout.addWidget(self.rename_group_button)
        right_panel.addLayout(buttons_layout)

        # Add right panel to splitter
        right_widget = QWidget()
        right_widget.setLayout(right_panel)
        splitter.addWidget(right_widget)

        # Set initial sizes for splitter (left panel smaller)
        splitter.setSizes([200, 600])

        # Set main widget
        central_widget = QWidget()
        central_layout = QHBoxLayout()
        central_layout.addWidget(splitter)
        central_widget.setLayout(central_layout)
        self.setCentralWidget(central_widget)

        # Initialize forwarding fields
        self.local_forward_fields = []
        self.remote_forward_fields = []
        self.dynamic_forward_fields = []

    def browse_identity_file(self):
        """Open a file dialog to select the IdentityFile path."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Identity File", str(Path.home() / ".ssh"), "All Files (*)"
        )
        if file_path:
            # Normalize path for cross-platform compatibility
            file_path = str(Path(file_path))
            if file_path.startswith(str(Path.home())): 
                file_path = f"~/{Path(file_path).relative_to(Path.home())}"
            self.identity_file_edit.setText(file_path)

    def add_local_forward(self):
        """Add fields for a new LocalForward option."""
        forward_widget = QWidget()
        forward_layout = QHBoxLayout()
        local_port = QSpinBox()
        local_port.setRange(1, 65535)
        remote_host = QLineEdit()
        remote_host.setPlaceholderText("Remote host")
        remote_port = QSpinBox()
        remote_port.setRange(1, 65535)
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.local_forward_fields))
        forward_layout.addWidget(local_port)
        forward_layout.addWidget(QLabel("to"))
        forward_layout.addWidget(remote_host)
        forward_layout.addWidget(QLabel(":"))
        forward_layout.addWidget(remote_port)
        forward_layout.addWidget(remove_button)
        forward_widget.setLayout(forward_layout)
        self.local_forward_layout.addWidget(forward_widget)
        self.local_forward_fields.append((forward_widget, local_port, remote_host, remote_port))

    def add_remote_forward(self):
        """Add fields for a new RemoteForward option."""
        forward_widget = QWidget()
        forward_layout = QHBoxLayout()
        remote_port = QSpinBox()
        remote_port.setRange(1, 65535)
        local_host = QLineEdit()
        local_host.setPlaceholderText("Local host")
        local_port = QSpinBox()
        local_port.setRange(1, 65535)
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.remote_forward_fields))
        forward_layout.addWidget(remote_port)
        forward_layout.addWidget(QLabel("to"))
        forward_layout.addWidget(local_host)
        forward_layout.addWidget(QLabel(":"))
        forward_layout.addWidget(local_port)
        forward_layout.addWidget(remove_button)
        forward_widget.setLayout(forward_layout)
        self.remote_forward_layout.addWidget(forward_widget)
        self.remote_forward_fields.append((forward_widget, remote_port, local_host, local_port))

    def add_dynamic_forward(self):
        """Add fields for a new DynamicForward option."""
        forward_widget = QWidget()
        forward_layout = QHBoxLayout()
        port = QSpinBox()
        port.setRange(1, 65535)
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.dynamic_forward_fields))
        forward_layout.addWidget(QLabel("Port:"))
        forward_layout.addWidget(port)
        forward_layout.addWidget(remove_button)
        forward_widget.setLayout(forward_layout)
        self.dynamic_forward_layout.addWidget(forward_widget)
        self.dynamic_forward_fields.append((forward_widget, port))

    def remove_forward(self, widget, fields_list):
        """Remove a forwarding field."""
        widget.deleteLater()
        for i, field in enumerate(fields_list):
            if field[0] == widget:
                fields_list.pop(i)
                break

    def add_other_option(self):
        """Add a row to the other options table."""
        row = self.other_options_table.rowCount()
        self.other_options_table.insertRow(row)
        self.other_options_table.setItem(row, 0, QTableWidgetItem(""))
        self.other_options_table.setItem(row, 1, QTableWidgetItem(""))

    def is_valid_hostname(self, hostname):
        """Validate if hostname is a valid IP or domain name."""
        if not hostname:
            return False
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        domain_pattern = r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$"
        return bool(re.match(ip_pattern, hostname) or re.match(domain_pattern, hostname))

    def validate_option(self, key, value):
        """Validate SSH option format."""
        if not value or not key:
            return True, ""
        key = key.lower()
        if key == "port":
            if not value.isdigit() or not (1 <= int(value) <= 65535):
                return False, "Port must be a number between 1 and 65535"
        elif key == "hostname" and not self.is_valid_hostname(value):
            return False, "Invalid HostName (must be IP or domain)"
        elif key == "proxyjump":
            return True, ""
        elif key in ("localforward", "remoteforward"):
            parts = value.split()
            if len(parts) != 2 or not parts[0].isdigit() or not (1 <= int(parts[0]) <= 65535):
                return False, f"{key} must be in format 'local_port remote_host:remote_port'"
            remote_host_port = parts[1].split(":")
            if len(remote_host_port) != 2 or not remote_host_port[1].isdigit() or not (1 <= int(remote_host_port[1]) <= 65535):
                return False, f"{key} remote host must be in format 'host:port'"
            if not self.is_valid_hostname(remote_host_port[0]):
                return False, f"{key} remote host must be valid IP or domain"
        elif key == "dynamicforward":
            if not value.isdigit() or not (1 <= int(value) <= 65535):
                return False, "DynamicForward must be a port number between 1 and 65535"
        elif key == "connecttimeout":
            if not value.isdigit() or int(value) < 0:
                return False, "ConnectTimeout must be a non-negative number"
        elif key == "stricthostkeychecking":
            if value not in ("yes", "no", "ask"):
                return False, "StrictHostKeyChecking must be 'yes', 'no', or 'ask'"
        return True, ""

    def load_config(self):
        """Parse SSH config file and populate hosts list."""
        self.hosts = {}
        self.global_options = []
        current_group = "Default"
        current_host = None
        in_global_section = False

        try:
            with open(self.ssh_config_path, "r") as f:
                lines = f.readlines()

            i = 0
            while i < len(lines):
                line = lines[i]
                stripped_line = line.strip()

                # Check for three-line group header
                if (
                    i + 2 < len(lines) and
                    stripped_line.startswith("##") and
                    lines[i + 1].strip().startswith("#") and
                    lines[i + 2].strip().startswith("##")
                ):
                    current_group = lines[i + 1].strip().lstrip("#").strip() or "Unnamed Group"
                    if current_group not in self.hosts:
                        self.hosts[current_group] = []
                    i += 3
                    continue

                # Fallback: detect single-line group headers
                if stripped_line.startswith("##") and not stripped_line[2:].strip():
                    current_group = stripped_line.strip("#").strip() or "Unnamed Group"
                    if current_group not in self.hosts:
                        self.hosts[current_group] = []
                    i += 1
                    continue

                # Skip empty lines and non-relevant comments
                if not stripped_line or (stripped_line.startswith("#") and not stripped_line[1:].strip()):
                    i += 1
                    continue

                # Detect Host directive
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

                # Add options
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
            QMessageBox.critical(self, "Error", f"Failed to parse config: {str(e)}")

    def update_hosts_tree(self):
        """Update the QTreeWidget with hosts grouped by sections."""
        self.hosts_tree.clear()
        selected_group = self.group_filter.currentText()

        if self.global_options and (selected_group == "All" or selected_group == "Global Settings"):
            global_item = QTreeWidgetItem(self.hosts_tree, ["Global Settings"])
            global_item.setForeground(0, QColor(0, 0, 255))
            global_item.setBackground(0, QColor(240, 240, 240))
            global_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            host_item = QTreeWidgetItem(global_item, ["Host *"])
            host_item.setData(0, Qt.ItemDataRole.UserRole, ("Global", "*"))
            global_item.setExpanded(True)

        for group, hosts in self.hosts.items():
            if selected_group != "All" and selected_group != group:
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
        """Update the QComboBox with available groups."""
        current = self.group_filter.currentText()
        self.group_filter.clear()
        self.group_filter.addItem("All")
        self.group_filter.addItem("Global Settings")
        for group in sorted(self.hosts.keys()):
            self.group_filter.addItem(group)
        index = self.group_filter.findText(current)
        if index >= 0:
            self.group_filter.setCurrentIndex(index)
        else:
            self.group_filter.setCurrentIndex(0)

    def update_proxy_jump_options(self):
        """Update ProxyJump QComboBox with available hosts."""
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
        """Filter the tree based on selected group."""
        self.update_hosts_tree()

    def filter_hosts(self, text):
        """Filter hosts based on search text."""
        self.update_hosts_tree()

    def on_host_selected(self, item, column):
        """Load host details when clicked."""
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return

        group, host_name = data
        self.current_host = (group, host_name)

        # Clear previous forwarding fields
        for widget, _, _, _ in self.local_forward_fields + self.remote_forward_fields:
            widget.deleteLater()
        for widget, _ in self.dynamic_forward_fields:
            widget.deleteLater()
        self.local_forward_fields = []
        self.remote_forward_fields = []
        self.dynamic_forward_fields = []
        self.other_options_table.setRowCount(0)

        if group == "Global" and host_name == "*":
            self.group_edit.setText("Global")
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
        """Load options into UI fields."""
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
                remove_button = QPushButton("Remove")
                remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.local_forward_fields))
                forward_layout.addWidget(lp)
                forward_layout.addWidget(QLabel("to"))
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
                remove_button = QPushButton("Remove")
                remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.remote_forward_fields))
                forward_layout.addWidget(rp)
                forward_layout.addWidget(QLabel("to"))
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
                remove_button = QPushButton("Remove")
                remove_button.clicked.connect(lambda: self.remove_forward(forward_widget, self.dynamic_forward_fields))
                forward_layout.addWidget(QLabel("Port:"))
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
        """Check if host name is unique, excluding the old name if updating."""
        for g, hosts in self.hosts.items():
            if g == old_group and name == old_name:
                continue
            for host in hosts:
                if host["name"] == name:
                    return False
        return True

    def save_host(self):
        """Save changes to the current host."""
        if not self.current_host:
            QMessageBox.warning(self, "Warning", "No host selected")
            return

        old_group, old_name = self.current_host
        new_group = self.group_edit.text().strip() or "Default"
        new_name = self.host_edit.text().strip()
        new_options = []
        new_raw_options = []

        if not new_name:
            QMessageBox.warning(self, "Warning", "Host name cannot be empty")
            return

        # Collect options from fields
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

        # Other options
        for row in range(self.other_options_table.rowCount()):
            key_item = self.other_options_table.item(row, 0)
            value_item = self.other_options_table.item(row, 1)
            key = key_item.text().strip() if key_item else ""
            value = value_item.text().strip() if value_item else ""
            if key and value:
                new_options.append(f"{key} {value}")
                new_raw_options.append(f"\t{key} {value}")

        # Validate options
        for option in new_options:
            parts = option.split(maxsplit=1)
            key = parts[0]
            value = parts[1] if len(parts) > 1 else ""
            valid, error = self.validate_option(key, value)
            if not valid:
                QMessageBox.warning(self, "Invalid Option", error)
                return

        # Check host uniqueness
        if not self.is_host_unique(new_group, new_name, old_group, old_name):
            QMessageBox.warning(self, "Warning", f"Host '{new_name}' already exists")
            return

        if old_name == "*":
            self.global_options = new_raw_options
            self.update_hosts_tree()
            self.update_group_filter()
            self.update_proxy_jump_options()
            self.save_config()
            return

        # Find and update the host
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
        """Delete the current host."""
        if not self.current_host:
            QMessageBox.warning(self, "Warning", "No host selected")
            return

        group, name = self.current_host
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete host '{name}' from group '{group}'?",
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

    def clear_options_fields(self):
        """Clear all options fields."""
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
        """Add a new host."""
        if not self.hosts:
            self.hosts["Default"] = []

        group, ok = QInputDialog.getItem(
            self, "Add Host", "Select group:",
            list(self.hosts.keys()), 0, False
        )
        if not ok:
            return

        name, ok = QInputDialog.getText(
            self, "Add Host", "Enter host name:",
            QLineEdit.EchoMode.Normal
        )
        if not ok or not name.strip():
            return

        name = name.strip()
        if not self.is_host_unique(group, name):
            QMessageBox.warning(self, "Warning", f"Host '{name}' already exists")
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
        """Add a new group."""
        group_name, ok = QInputDialog.getText(
            self, "Add Group", "Enter group name:",
            QLineEdit.EchoMode.Normal
        )
        if ok and group_name.strip():
            if group_name.strip() not in self.hosts:
                self.hosts[group_name.strip()] = []
                self.update_hosts_tree()
                self.update_group_filter()

    def rename_group(self):
        """Rename an existing group."""
        old_group, ok = QInputDialog.getItem(
            self, "Rename Group", "Select group:",
            list(self.hosts.keys()), 0, False
        )
        if not ok:
            return

        new_group, ok = QInputDialog.getText(
            self, "Rename Group", "Enter new group name:",
            QLineEdit.EchoMode.Normal
        )
        if ok and new_group.strip() and new_group.strip() not in self.hosts:
            self.hosts[new_group.strip()] = self.hosts.pop(old_group)
            if self.current_host and self.current_host[0] == old_group:
                self.current_host = (new_group.strip(), self.current_host[1])
            self.update_hosts_tree()
            self.update_group_filter()
            self.save_config()

    def save_config(self):
        """Save the current configuration back to the SSH config file."""
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
            QMessageBox.information(self, "Success", "SSH config saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save config: {str(e)}")


if __name__ == "__main__":
    app = QApplication([])
    editor = SSHConfigEditor()
    editor.show()
    app.exec()