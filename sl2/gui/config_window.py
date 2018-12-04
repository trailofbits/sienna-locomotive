import os
import re

from PySide2 import QtWidgets
from PySide2.QtCore import Qt, QSize
from PySide2.QtWidgets import QFileDialog, QStyle

from sl2.harness import config


## class ConfigWindow
#  Helper gui window for selecting an existing target configuration or creating a new one
class ConfigWindow(QtWidgets.QDialog):

    ## build window, add widgets, connect callbacks
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

        # Create widgets for profile selection
        self.okay_button = QtWidgets.QPushButton("Use Profile")
        self.okay_button.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Preferred)
        self.okay_button.clicked.connect(self.accept)

        self.profiles = QtWidgets.QComboBox()
        self.profiles.addItems(list(config._config.keys()))

        cbox_layout.addWidget(self.profiles)
        cbox_layout.addWidget(self.okay_button)
        self._layout.addLayout(cbox_layout)

        # Create layout and widgets for adding a new profile
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

        # set placeholder text in path text boxes
        self.profile_name.setPlaceholderText("Profile Name")
        # self.drrun_path.setPlaceholderText("Path to drrun.exe")
        self.drrun_path.setText(config._config["DEFAULT"]["drrun_path"])

        # self.build_dir.setPlaceholderText("Path to SL2 build directory")
        self.build_dir.setText(
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))), "build")
        )

        self.target_path.setPlaceholderText("Path to target application")
        self.target_args.setPlaceholderText("Target arguments")

        # Create buttons for adding paths
        self.drrun_path_button = QtWidgets.QPushButton("Choose Path")
        self.build_dir_button = QtWidgets.QPushButton("Choose Directory")
        self.target_path_button = QtWidgets.QPushButton("Choose Target")

        icon = self.style().standardIcon(QStyle.SP_MessageBoxCritical)
        self.bad_profile_name_warning = QtWidgets.QLabel()
        self.bad_profile_name_warning.setPixmap(icon.pixmap(32, 32))
        self.bad_profile_name_warning.hide()

        # Create warning messages for incorrect paths
        icon = self.style().standardIcon(QStyle.SP_MessageBoxWarning)
        self.bad_dr_path_warning = QtWidgets.QLabel()
        self.bad_dr_path_warning.setPixmap(icon.pixmap(32, 32))
        self.bad_dr_path_warning.setToolTip(
            "This path doesn't look quite right. It might be invalid, or drrun.exe may have been moved?"
        )
        self.bad_dr_path_warning.hide()

        icon = self.style().standardIcon(QStyle.SP_MessageBoxCritical)
        self.bad_build_dir_warning = QtWidgets.QLabel()
        self.bad_build_dir_warning.setPixmap(icon.pixmap(32, 32))
        self.bad_build_dir_warning.setToolTip("This build root is missing some expected child paths.")
        self.bad_build_dir_warning.hide()

        profile_name_layout = QtWidgets.QHBoxLayout()
        # Create layouts for adding the new profile UI components
        drrun_path_layout = QtWidgets.QHBoxLayout()
        build_dir_layout = QtWidgets.QHBoxLayout()
        target_path_layout = QtWidgets.QHBoxLayout()

        profile_name_layout.addWidget(self.profile_name)
        profile_name_layout.addWidget(self.bad_profile_name_warning)

        drrun_path_layout.addWidget(self.drrun_path)
        drrun_path_layout.addWidget(self.drrun_path_button)
        drrun_path_layout.addWidget(self.bad_dr_path_warning)

        build_dir_layout.addWidget(self.build_dir)
        build_dir_layout.addWidget(self.build_dir_button)
        build_dir_layout.addWidget(self.bad_build_dir_warning)

        target_path_layout.addWidget(self.target_path)
        target_path_layout.addWidget(self.target_path_button)

        self.extension_layout.addLayout(profile_name_layout)
        self.extension_layout.addLayout(drrun_path_layout)
        self.extension_layout.addLayout(build_dir_layout)
        self.extension_layout.addLayout(target_path_layout)
        self.extension_layout.addWidget(self.target_args)

        self.add_button = QtWidgets.QPushButton("Add")
        self.extension_layout.addWidget(self.add_button)

        self.extension_widget.setLayout(self.extension_layout)
        self._layout.addWidget(self.extension_widget)
        self.extension_widget.hide()

        # Connect the signals to the callbacks
        self.expand_button.clicked.connect(self.toggle_expansion)
        self.add_button.clicked.connect(self.add_config)
        self.drrun_path_button.clicked.connect(self.get_drrun_path)
        self.build_dir_button.clicked.connect(self.get_build_dir)
        self.target_path_button.clicked.connect(self.get_target_path)
        self.profile_name.textChanged.connect(self.validate_profile_name)
        self.drrun_path.textChanged.connect(self.validate_drrun_path)
        self.build_dir.textChanged.connect(self.validate_build_path)

        self.show()
        if config.profile != "DEFAULT":
            self.profiles.setCurrentText(config.profile)

    ## When the "Add Config" button is clicked, read the values from the text boxes and write them into the config file
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
        config.create_new_profile(
            name,
            os.path.normpath(self.drrun_path.text()),
            os.path.normpath(self.build_dir.text()),
            os.path.normpath(self.target_path.text()),
            self.target_args.text(),
        )

        self.profiles.clear()
        profile_names = list(config._config.keys())
        self.profiles.addItems(profile_names)
        self.profiles.setCurrentIndex(profile_names.index(name))
        self.expand_button.click()

    ## Push the current profile into the config module
    def done(self, *args):
        config.set_profile(self.profiles.currentText())
        super().done(*args)

    ## Get the path returned by the Qt dialog
    def get_drrun_path(self):
        path, good = QFileDialog.getOpenFileName(filter="*.exe", dir=config._config["DEFAULT"]["drrun_path"])
        if good:
            self.drrun_path.setText(path)

    ## Get the path returned by the Qt dialog
    def get_target_path(self):
        path, good = QFileDialog.getOpenFileName(filter="*.exe")
        if good:
            self.target_path.setText(path)

    ## Get the path returned by the Qt dialog
    def get_build_dir(self):
        path = QFileDialog.getExistingDirectory(dir="build")
        if len(path) > 0:
            self.build_dir.setText(path)

    def validate_profile_name(self, new_profile_name):
        if len(new_profile_name) > 32:
            self.bad_profile_name_warning.show()
            self.bad_profile_name_warning.setToolTip(
                "Profile name is too long ({} > 32).".format(len(new_profile_name))
            )
            self.add_button.setEnabled(False)
        elif not re.match("^[a-zA-Z1-9]+$", new_profile_name):
            self.bad_profile_name_warning.show()
            self.bad_profile_name_warning.setToolTip("Profile name isn't alphanumeric.")
            self.add_button.setEnabled(False)
        else:
            self.bad_profile_name_warning.hide()
            self.add_button.setEnabled(True)

    ## Validate the path to drrun.exe
    def validate_drrun_path(self, new_path):
        good = "drrun.exe" in new_path
        good = good and ("bin32" in new_path or "bin64" in new_path)
        good = good and os.path.isfile(new_path)

        if not good:
            self.bad_dr_path_warning.show()
            self.add_button.setEnabled(False)
        else:
            self.bad_dr_path_warning.hide()
            self.add_button.setEnabled(True)

    ## Validate the path to the build directory
    def validate_build_path(self, new_path):
        paths = [
            "server\\Debug\\server.exe",
            "fuzzer\\Debug\\fuzzer.dll",
            "wizard\\Debug\\wizard.dll",
            "tracer\\Debug\\tracer.dll",
        ]
        missing = []
        for path in paths:
            if not os.path.isfile(os.path.join(new_path, path)):
                missing.append(path)
        if len(missing) > 0:
            self.bad_build_dir_warning.show()
            self.bad_build_dir_warning.setToolTip(
                "This build root is missing some expected child paths: " + "\n".join(missing)
            )
            self.add_button.setEnabled(False)
        else:
            self.bad_build_dir_warning.hide()
            self.add_button.setEnabled(True)

    ## Show and hide the 'new profile' dialog
    def toggle_expansion(self):
        if not self.extension_widget.isVisible():
            self.extension_widget.show()
            self.expand_button.setArrowType(Qt.DownArrow)
            self.add_button.setDefault(True)
            self.okay_button.setDefault(False)
        else:
            self.extension_widget.hide()
            self.expand_button.setArrowType(Qt.RightArrow)
            self.okay_button.setDefault(True)
            self.add_button.setDefault(False)
        self.adjustSize()
