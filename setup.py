import setuptools

long_description = open("README.md").read()

setuptools.setup(
    name="seaoftacos-pkg-Zeta314", # Replace with your own username
    version="0.0.1",
    author="Zeta314",
    author_email="ale3152001@gmail.com",
    description="A process interaction package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Zeta314/Sea-of-Tacos",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Windows",
    ],
    python_requires='>=3.6',
)