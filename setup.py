from setuptools import setup, find_packages

setup(
    name='PrivacyNet',
    version='1.0.0',
    description='Anonymization tool for configuring iptables and Tor.',
    long_description=open('Readme.md').read(),
    long_description_content_type='text/markdown',
    author='Halil Deniz',
    author_email='halildeniz313@gmail.com',
    url='https://github.com/HalilDeniz/PrivacyNet',
    packages=find_packages(),
    install_requires=[
        'colorama',
    ],
    entry_points={
        'console_scripts': [
            'privacynet=privacynet.privacynet:privacynet',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    python_requires='>=3.6',
)
