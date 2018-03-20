from setuptools import setup
from codecs import open
from os import path
from zio3 import __version__

here = path.abspath(path.dirname(__file__))
# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='zio3',
    version=__version__,

    author='Alset0326',
    author_email='alset0326@gmail.com',
    url='https://github.com/alset0326/zio',

    license='LICENSE.txt',
    keywords="zio pwning io expect-like",
    description='Unified io lib for pwning development written in python.',
    long_description=long_description,

    py_modules=['zio3'],

    # Refers to test/test.py
    test_suite='test.test',

    entry_points={
        'console_scripts': [
            'zio3=zio3:main'
        ]
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Operating System :: POSIX',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development',
        'Topic :: System',
        'Topic :: Terminals',
        'Topic :: Utilities',
    ],
)
