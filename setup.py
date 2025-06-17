from setuptools import setup, find_packages
import PyAsyncDNS as package

setup(
    name='PyAsyncDNS',
    version=package.__version__,
    py_modules=[],
    packages=find_packages(include=['PyAsyncDNS']),
    install_requires=[],
    scripts=[],
    author="Maurice Lambert",
    author_email="mauricelambert434@gmail.com",
    maintainer="Maurice Lambert",
    maintainer_email="mauricelambert434@gmail.com",
    description='This package implements a basic asynchronous DNS client and server with a feature to exfiltrate data through DNS.',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mauricelambert/PyAsyncDNS",
    project_urls={
        "Github": "https://github.com/mauricelambert/PyAsyncDNS",
        "Documentation": "https://mauricelambert.github.io/info/python/security/PyAsyncDNS.html",
        "Python Executable": "https://mauricelambert.github.io/info/python/security/PyAsyncDNS.pyz",
        "Windows Executable": "https://mauricelambert.github.io/info/python/security/PyAsyncDNS.exe",
    },
    download_url="https://mauricelambert.github.io/info/python/security/PyAsyncDNS.pyz",
    include_package_data=True,
    classifiers=[
        "Topic :: Security",
        "Environment :: Console",
        "Topic :: System :: Shells",
        'Operating System :: POSIX',
        "Natural Language :: English",
        "Topic :: System :: Networking",
        "Programming Language :: Python",
        "Intended Audience :: Developers",
        "Topic :: System :: System Shells",
        'Operating System :: MacOS :: MacOS X',
        "Programming Language :: Python :: 3.8",
        'Operating System :: Microsoft :: Windows',
        "Topic :: System :: Systems Administration",
        "Intended Audience :: System Administrators",
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    keywords=['DNS', 'client', 'server', 'exfiltration', 'data-exfiltration', 'dns-client', 'dns-server', 'dns-exfiltration', 'asynchronous'],
    platforms=['Windows', 'Linux', "MacOS"],
    license="GPL-3.0 License",
    entry_points = {
        'console_scripts': [
            'PyAsyncDNS = PyAsyncDNS:main'
        ],
    },
    python_requires='>=3.8',
)