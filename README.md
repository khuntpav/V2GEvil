# V2GEvil

This project will serve as an evaluation tool for V2G communication between a car and a station. It mainly focuses on the part of the communication from and to the car.

In the futrue there will be two parts:
- Evil car: to exploit stations
- Evil station: to exploit cars

## How to make it running
~~I use pip in combination with pyproject.toml. I also use the pyenv with virtualenv plugin to manage Python version and dependencies.~~

I use poetry together with pyproject.toml. Steps are belo2 this section.

Starting with PEP 621, the Python community selected pyproject.toml as a standard way of specifying project metadata [Setuptools pyproject config](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html).

### ~~Old Steps~~
#### 1. ~~Clone this repository~~
#### 2. ~~cd to the repository~~
#### 3. ~~Use pyenv virtualenv to create virtualenv for this project~~
```bash
# $VERSION - specific version of Python, recommended 3.10.12
VERSION="3.10.12"
NAME="V2GEvil"

V2GEvil:~/V2GEvil$ pyenv install "$VERSION"
V2GEvil:~/V2GEvil$ pyenv virtualenv "$VERSION" "$NAME"
V2GEvil:~/V2GEvil$ pyenv activate "$NAME"

```
#### 4. ~~Install it as package~~
```bash

# Virtualevn is activated
(V2GEvil) V2GEvil:~/V2GEvil$ pip3 install -e . # For development
(V2GEvil) V2GEvil:~/V2GEvil$ pip3 install . # Normal install
```

I changed my strategy because it's not working. The virtualenv in pyenv is sometimes broken...
I had to move to use poetry.

### New Steps
#### 1. Clone this repository
#### 2. cd to the repository
#### 3. Install poetry
#### 4. Execute following commands
```bash
V2GEvil:~/V2GEvil$ poetry install
V2GEvil:~/V2GEvil$ poetry shell
(v2gevil-py3.10) V2GEvil:~/V2GEvil$ v2gevil
```

## Usage
```bash
# Name can be changed in pyproject.toml -> [tool.poetry.scripts]
(V2GEvil) V2GEvil:~/V2GEvil$ v2gevil --help
```


## Documentation
I will use [mkdocs materials](https://squidfunk.github.io/mkdocs-material/getting-started/) for the documentation purposes.
