import setuptools
from pathlib import Path

README = (Path(__file__).parent/"README.md").read_text()

setuptools.setup(
    name="streamlit-oauth",
    version="0.0.2",
    author="Dylan Lu",
    author_email="",
    description="Simple OAuth2 authorization code flow for Streamlit",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/dnplus/streamlit-oauth",
    packages=setuptools.find_packages(),
    include_package_data=True,
    classifiers=[],
    python_requires=">=3.9",
    install_requires=[
        # By definition, a Custom Component depends on Streamlit.
        # If your component has other Python dependencies, list
        # them here.
        "streamlit>=0.81.1",
        "httpx-oauth>=0.3.5"
    ],
)