
from PySide2.QtWidgets import QFileDialog, QStyle
from PySide2 import QtWidgets
from PySide2.QtCore import Qt, QSize
import os

from harness import config


class ConfigWindow(QtWidgets.QDialog):

    def __init__(self):
        QtWidgets.QDialog.__init__(self)

        # Select config profile before starting

        # Set up basic window
        self.setWindowTitle("Configure SL2")
        self.setMinimumSize(QSize(800, 200))

        self._layout = QtWidgets.QVBoxLayout()
        self.setLayout(self._layout)
        self._layout.setAlignment(Qt.AlignTop)

        # CREATE WIDGETS #
        cbox_layout = QtWidgets.QHBoxLayout()

        self.okay_button = QtWidgets.QPushButton("Use Profile")
        self.okay_button.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Preferred)
        self.okay_button.clicked.connect(self.accept)

        self.profiles = QtWidgets.QComboBox()
        self.profiles.addItems(list(config._config.keys()))

        cbox_layout.addWidget(self.profiles)
        cbox_layout.addWidget(self.okay_button)
        self._layout.addLayout(cbox_layout)

        expansion_layout = QtWidgets.QHBoxLayout()
        expansion_layout.setAlignment(Qt.AlignLeft)
        add_label = QtWidgets.QLabel("Add Profile ")
        expansion_layout.addWidget(add_label)
        self.expand_button = QtWidgets.QToolButton()
        self.expand_button.setArrowType(Qt.RightArrow)
        expansion_layout.addWidget(self.expand_button)
        self._layout.addLayout(expansion_layout)

        self.extension_widget = QtWidgets.QWidget()
        self.extension_layout = QtWidgets.QVBoxLayout()

        self.profile_name = QtWidgets.QLineEdit()
        self.drrun_path = QtWidgets.QLineEdit()
        self.build_dir = QtWidgets.QLineEdit()
        self.target_path = QtWidgets.QLineEdit()
        self.target_args = QtWidgets.QLineEdit()

        self.profile_name.setPlaceholderText("Profile Name")
        #self.drrun_path.setPlaceholderText("Path to drrun.exe")
        self.drrun_path.setText(config._config['DEFAULT']['drrun_path'])

        #self.build_dir.setPlaceholderText("Path to SL2 build directory")
        self.build_dir.setText("build")

        self.target_path.setPlaceholderText("Path to target application")
        self.target_args.setPlaceholderText("Target arguments")

        self.drrun_path_button = QtWidgets.QPushButton("Choose Path")
        self.build_dir_button = QtWidgets.QPushButton("Choose Directory")
        self.target_path_button = QtWidgets.QPushButton("Choose Target")

        icon = self.style().standardIcon(QStyle.SP_MessageBoxWarning)
        self.bad_dr_path_warning = QtWidgets.QLabel()
        self.bad_dr_path_warning.setPixmap(icon.pixmap(32, 32))
        self.bad_dr_path_warning.setToolTip("This path doesn't look quite right. It might be invalid, or drrun.exe may have been moved?")
        self.bad_dr_path_warning.hide()

        icon = self.style().standardIcon(QStyle.SP_MessageBoxCritical)
        self.bad_build_dir_warning = QtWidgets.QLabel()
        self.bad_build_dir_warning.setPixmap(icon.pixmap(32, 32))
        self.bad_build_dir_warning.setToolTip("This build root is missing some expected child paths")
        self.bad_build_dir_warning.hide()

        drrun_path_layout = QtWidgets.QHBoxLayout()
        build_dir_layout = QtWidgets.QHBoxLayout()
        target_path_layout = QtWidgets.QHBoxLayout()

        drrun_path_layout.addWidget(self.drrun_path)
        drrun_path_layout.addWidget(self.drrun_path_button)
        drrun_path_layout.addWidget(self.bad_dr_path_warning)

        build_dir_layout.addWidget(self.build_dir)
        build_dir_layout.addWidget(self.build_dir_button)
        build_dir_layout.addWidget(self.bad_build_dir_warning)

        target_path_layout.addWidget(self.target_path)
        target_path_layout.addWidget(self.target_path_button)

        self.extension_layout.addWidget(self.profile_name)
        self.extension_layout.addLayout(drrun_path_layout)
        self.extension_layout.addLayout(build_dir_layout)
        self.extension_layout.addLayout(target_path_layout)
        self.extension_layout.addWidget(self.target_args)

        self.add_button = QtWidgets.QPushButton("Add")
        self.extension_layout.addWidget(self.add_button)

        self.extension_widget.setLayout(self.extension_layout)
        self._layout.addWidget(self.extension_widget)
        self.extension_widget.hide()

        self.expand_button.clicked.connect(self.toggle_expansion)
        self.add_button.clicked.connect(self.add_config)
        self.drrun_path_button.clicked.connect(self.get_drrun_path)
        self.build_dir_button.clicked.connect(self.get_build_dir)
        self.target_path_button.clicked.connect(self.get_target_path)
        self.drrun_path.textChanged.connect(self.validate_drrun_path)
        self.build_dir.textChanged.connect(self.validate_build_path)

        self.show()

    def add_config(self, *_args):
        name = self.profile_name.text()
        if len(name) == 0:
            QtWidgets.QMessageBox.critical(self, "Invalid Name", "Profile name cannot be empty")
            return
        if len(self.drrun_path.text()) == 0:
            QtWidgets.QMessageBox.critical(self, "Invalid Path", "Path to drrun.exe cannot be empty")
            return
        if len(self.build_dir.text()) == 0:
            QtWidgets.QMessageBox.critical(self, "Invalid Path", "Path to build directory cannot be empty")
            return
        if len(self.target_path.text()) == 0:
            QtWidgets.QMessageBox.critical(self, "Invalid Path", "Target application path cannot be empty")
            return
        config.create_new_profile(name, os.path.normpath(self.drrun_path.text()), os.path.normpath(self.build_dir.text()),
                                  os.path.normpath(self.target_path.text()), self.target_args.text())

        self.profiles.clear()
        profile_names = list(config._config.keys())
        self.profiles.addItems(profile_names)
        self.profiles.setCurrentIndex(profile_names.index(name))
        self.expand_button.click()

    def done(self, *args):
        config.set_profile(self.profiles.currentText())
        super().done(*args)

    def get_drrun_path(self):
        path, good = QFileDialog.getOpenFileName(filter="*.exe", dir=config._config['DEFAULT']['drrun_path'])
        if good:
            self.drrun_path.setText(path)

    def get_target_path(self):
        path, good = QFileDialog.getOpenFileName(filter="*.exe")
        if good:
            self.target_path.setText(path)

    def get_build_dir(self):
        path = QFileDialog.getExistingDirectory(dir='build')
        if len(path) > 0:
            self.build_dir.setText(path)

    def validate_drrun_path(self, new_path):
        good = 'drrun.exe' in new_path
        good = good and ('bin32' in new_path or 'bin64' in new_path)
        good = good and os.path.isfile(new_path)

        if not good:
            self.bad_dr_path_warning.show()
        else:
            self.bad_dr_path_warning.hide()

    def validate_build_path(self, new_path):
        paths = ['server\\Debug\\server.exe',
                 'fuzz_dynamorio\\Debug\\fuzzer.dll',
                 'wizard\\Debug\\wizard.dll',
                 'triage_dynamorio\\Debug\\tracer.dll']
        missing = []
        for path in paths:
            if not os.path.isfile(os.path.join(new_path, path)):
                missing.append(path)
        if len(missing) > 0:
            self.bad_build_dir_warning.show()
            self.bad_build_dir_warning.setToolTip("This build root is missing some expected child paths: " + '\n'.join(missing))
        else:
            self.bad_build_dir_warning.hide()


    def toggle_expansion(self):
        if not self.extension_widget.isVisible():
            self.extension_widget.show()
            self.expand_button.setArrowType(Qt.DownArrow)
            self.adjustSize()
        else:
            self.extension_widget.hide()
            self.expand_button.setArrowType(Qt.RightArrow)
            self.adjustSize()