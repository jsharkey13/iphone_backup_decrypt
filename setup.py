from setuptools import setup, find_packages

setup(name='iphone_backup_decrypt',
      version='0.1',
      description='Decrypt an iOS13+ encrypted local backup.',
      url='https://github.com/jsharkey13/iphone_backup_decrypt',
      author='James Sharkey',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      install_requires=[
          'biplist',
          'pycryptodome'
      ],
      python_requires='>=3',
      classifiers=[
          'Programming Language :: Python :: 3'
      ])
