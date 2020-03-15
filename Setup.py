import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="leap-protocol",
    version="1.0.1",
    author="Hoani Bryson",
    author_email="hoani.bryson@gmail.com",
    description="Legible Encoding for Addressable Packets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/leap-protocol/leap-py",
    packages=setuptools.find_packages(exclude=["test", "*fake*"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
          'toml',
    ],
    python_requires='>=3.6',
)