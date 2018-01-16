# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name = "spymaster",
    version = "0.2",
    author = "Julio Dantas",
    description = "A pure python MFT parser",
    url = "https://github.com/jldantas/spymaster",
    license = "MIT License",
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
         "Development Status :: 2 - Pre-Alpha",
         "Environment :: Console",
         "Intended Audience :: Other Audience",
         "Intended Audience :: Information Technology",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
         "Programming Language :: Python :: 3.6",
         "Topic :: Security",
         "Topic :: System :: Filesystems"
    ],
    keywords = "mft parser python",
    install_requires=['libmft'],
    python_requires = ">=3.6",
    #packages = find_packages(exclude=['contrib', 'docs', 'tests*']),
    scripts = ["spymaster.py"]
)
