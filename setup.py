from setuptools import setup, find_packages

setup(
    name='sl2',
    version='0.2.dev1',
    description='A User-Friendly Fuzzing Tool',
    url='https://github.com/trailofbits/sienna-locomotive',
    author='Trail of Bits',
    packages=find_packages() + ['sl2.test'],
    long_description=open('README.md').read(),
    install_requires=[
        'msgpack',
        'PySide2',
        'sqlalchemy'
    ],
    entry_points={
        'console_scripts': [
            'sl2 = sl2.gui.__main__:main',
            'sl2-cli = sl2.harness.__main__:main',
            'sl2-triage = sl2.triage.__main__:main',
            'sl2-test = sl2.test.__main__:main'
        ],
        'gui_scripts': [
            'sl2-noconsole = sl2.gui.__main__:main'
        ]
    }
)
