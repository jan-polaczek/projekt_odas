from setuptools import setup

setup(
    name='app',
    packages=['app'],
    include_package_data=True,
    install_requires=[
        'flask', 'python-dotenv', 'bcrypt', 'flask_sqlalchemy', 'pymysql', 'sqlalchemy',
        'pyOpenSSL', 'email-validator', 'werkzeug', 'Flask-Mail', 'ipinfo', 'PyCryptodome'
    ],
)
