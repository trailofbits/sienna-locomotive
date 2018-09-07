from distutils.core import setup

setup(
    name='Sienna Locomotive 2',
    version='0.1dev',
    description='A User-Friendly Fuzzing Tool',
    url='https://github.com/trailofbits/sienna-locomotive',
    author='Trail of Bits',
    packages=['db', 'gui', 'harness'],
    long_description=open('README.md').read(),
    install_requires=[
        'msgpack',
        'PySide2',
        'sqlalchemy'
    ],
    entry_points={
        'console_scripts': [
            'sl2 = sl2.gui:main',
            'sl2-cli = sl2.harness:main'
        ]
    }
)
