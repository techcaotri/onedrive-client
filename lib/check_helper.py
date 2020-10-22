import subprocess
import os
from shutil import which


class quickxorhash:

  __COMMAND_NAME = 'quickxorhash'

  def __init__(self):
    self.program = which(self.__COMMAND_NAME)

  def quickxorhash(self, filename):

    if self.program is not None:
      p = subprocess.run([self.program, filename], stdout=subprocess.PIPE)
      if p.returncode != 0:
        return None
      else:
        return str(p.stdout, 'utf-8')[:-1]
    else:
      return None

  # How to get quickxorhash command
  #
  # git clone https://github.com/sndr-oss/quickxorhash-c.git
  #
  # apt install pkg-config libtool automake
  # autoreconf -i
  # ./configure
  # make
  #
  # -- installation ---
  # make install
  #
  # -- update cache of libraries from /etc/ld.so.conf
  # ldconfig
  #
  # -- uninstallation --
  # git clean -dfX
