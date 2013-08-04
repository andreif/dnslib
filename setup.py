# coding=utf-8
import dnslib
try:
    from setuptools import setup, Command
except ImportError:
    from distutils.core import setup, Command


class GenerateReadme(Command):
    description = "Generates README file from long_description"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        open('README', 'w').write(dnslib.__doc__)


setup(
    name='dnslib',
    version=dnslib.VERSION,
    description="Simple library to encode/decode DNS wire-format packets",
    long_description=dnslib.__doc__,
    author="Paul Chakravarti",
    author_email='paul.chakravarti@gmail.com',
    url='http://bitbucket.org/paulc/dnslib/',
    cmdclass={'readme': GenerateReadme},
    packages=['dnslib'],
    license='BSD',
    classifiers=['Topic :: Internet :: Name Service (DNS)'],
)
