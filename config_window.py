
from PyQt5.QtWidgets import QFileDialog, QMenu, QAction
from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt, QSize
from functools import partial

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
        self.profiles.addItems(config._config.keys())

        cbox_layout.addWidget(self.profiles)
        cbox_layout.addWidget(self.okay_button)
        self._layout.addLayout(cbox_layout)

        expansion_layout = QtWidgets.QHBoxLayout()
        expansion_layout.setAlignment(Qt.AlignLeft)
        add_label = QtWidgets.QLabel("Add Profile ")
        # add_label.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Preferred)
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
        self.drrun_path.setPlaceholderText("Path to drrun.exe")
        self.build_dir.setPlaceholderText("Path to SL2 build directory")
        self.target_path.setPlaceholderText("Path to target application")
        self.target_args.setPlaceholderText("Target arguments (comma separated)")

        self.drrun_path_button = QtWidgets.QPushButton("Choose Path")
        self.build_dir_button = QtWidgets.QPushButton("Choose Directory")
        self.target_path_button = QtWidgets.QPushButton("Choose Target")

        drrun_path_layout = QtWidgets.QHBoxLayout()
        build_dir_layout = QtWidgets.QHBoxLayout()
        target_path_layout = QtWidgets.QHBoxLayout()

        drrun_path_layout.addWidget(self.drrun_path)
        drrun_path_layout.addWidget(self.drrun_path_button)

        build_dir_layout.addWidget(self.build_dir)
        build_dir_layout.addWidget(self.build_dir_button)

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

        self.show()

    def add_config(self, *_args):
        name = self.profile_name.text()
        config.create_new_profile(name, self.drrun_path.text(), self.build_dir.text(),
                                  self.target_path.text(), self.target_args.text())

        self.profiles.clear()
        profile_names = list(config._config.keys())
        self.profiles.addItems(profile_names)
        self.profiles.setCurrentIndex(profile_names.index(name))
        self.expand_button.click()

    def done(self, *args):
        config.set_profile(self.profiles.currentText())
        super().done(*args)

    def get_drrun_path(self):
        path, good = QFileDialog.getOpenFileName(filter="*.exe", directory=config._config['DEFAULT']['drrun_path'])
        if good:
            self.drrun_path.setText(path)

    def get_target_path(self):
        path, good = QFileDialog.getOpenFileName(filter="*.exe")
        if good:
            self.target_path.setText(path)

    def get_build_dir(self):
        path = QFileDialog.getExistingDirectory(directory='build')
        if len(path) > 0:
            self.build_dir.setText(path)

    def toggle_expansion(self):
        if not self.extension_widget.isVisible():
            self.extension_widget.show()
            self.expand_button.setArrowType(Qt.DownArrow)
            self.adjustSize()
        else:
            self.extension_widget.hide()
            self.expand_button.setArrowType(Qt.RightArrow)
            self.adjustSize()