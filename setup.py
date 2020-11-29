import os
import setuptools

README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()

# pypi publishing
# 1. set $HOME/.pypirc
#      [distutils]
#      index-servers =
#          pypi
#
#      [pypi]
#      username: <name>
#      password: <password>
# 2. deactivate  // if there's an active env
# 3. cd pycharmenv3; source bin/activate
# 4. pip3 install --upgrade wheel setuptools twine
# 5. cd <whatever_to>/keychest-server
# 6. rm -rf dist/*
# 7. python3 setup.py sdist bdist_wheel
# 7a.twine check dist/*
# 8. twine upload dist/<latest>.tar.gz
# 9. you can test it with "pip3 install --upgrade --no-cache-dir keychest-server"


# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setuptools.setup(
    name='wizard_whois',
    version='2.5.9',
    packages=['wizard_whois'],
    package_dir={"wizard_whois": "wizard_whois"},
    package_data={"wizard_whois": ["*.dat"]},
    install_requires=['argparse'],
    provides=['wizard_whois'],
    scripts=["pwhois"],

    license="MIT",
    description='Module for retrieving and parsing the WHOIS data for a domain. Supports most domains. '
                'Fork of pythonwhois-alt and whois_alt as we need quick bug fixes',
    long_description=README,
    long_description_content_type="text/markdown",
    keywords='whois nic domain',

    author='Michael Ramsey',
    author_email='mike@hackerdise.me',
    url='https://gitlab.com/mikeramsey/whois-alt-for-python',

    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: Name Service (DNS)',
    ],
)
