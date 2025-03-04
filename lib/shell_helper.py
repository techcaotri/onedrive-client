#  Copyright 2019-2025 Jareth Lomson <jareth.lomson@gmail.com>
#  This file is part of OneDrive Client Program which is released under MIT License
#  See file LICENSE for full license details
import argparse
import logging
import os
import re
import shlex
import subprocess
import sys
import time
import traceback
from abc import ABC, abstractmethod
from datetime import datetime as dt
from io import StringIO
from pprint import pprint
from threading import Event, Thread, Lock

from beartype import beartype
from colorama import Fore, Style
from colorama import init as cinit

from lib._common import PROGRAM_NAME, get_versionned_name
from lib._typing import List, Optional, Tuple
from lib.graph_helper import MsGraphClient
from lib.msobject_info import DictMsObject, MsFileInfo, MsFolderInfo, MsObject
from lib.msobject_info import ObjectInfoFactory as OIF
from lib.msobject_info import StrPathUtil
from lib.printer_helper import (ColumnsPrinter, FormattedString, alignleft,
                                print_with_optional_paging)

try:
  import readline
except ModuleNotFoundError as e:
  print("It seems that you run this program from a Windows platform.")
  print("The pyreadline3 module is needed to run the shell")
  print("Use command 'pip install pyreadline3' to use it")

lg = logging.getLogger('odc.browser')


class CommonCompleter:
  """ Class to gather methods used in SubCompleter
  """

  @staticmethod
  def get_cmd_parts_with_quotation_guess(input):
    try:
      # WARNING: does not work with win32 if a backslash is included in input
      result = shlex.split(input)

    except ValueError as e:
      try:
        result = shlex.split(input + "'")

      except ValueError as e:
        result = shlex.split(input + '"')

    if len(result) >= 1 and input[-1] == " " and result[-1][-1] != " ":
      result.append("")

    return result

  @staticmethod
  def extract_raw_last_args(input, parsed_last_arg):
    """
      Extract raw last args (with quote and escape chars) from input line.
      parsed_last_args is the last argument without quote and escape chars.

      Return None if not found
    """
    # Build shlex to compute last arg
    s = shlex.shlex(punctuation_chars=" ")
    s.whitespace = "\t\r\n"
    s.quotes = ""
    s.escape = ""
    s.commenters = ''
    s.instream = StringIO(input)
    part_args = list(s)

    i = len(part_args) - 1
    raw_last_args = ""
    while i > 1:

      raw_last_args = part_args[i] + raw_last_args  # append last args to left
      part_std_shlex = CommonCompleter.get_cmd_parts_with_quotation_guess(
          raw_last_args)

      if len(part_std_shlex) > 0:
        last_arg_std_shlex = part_std_shlex[0]
      else:
        last_arg_std_shlex = ""

      if parsed_last_arg == last_arg_std_shlex:  # found !
        if part_args[i - 1][-1] != " ":
          raw_last_args = raw_last_args + part_args[i - 1]  # probably a quote
        return raw_last_args

      i = i - 1

   # self.__log_debug(f'extract_raw_last_args("{input}","{parsed_last_arg}")
   # not found')
    return None


class SubCompleter(ABC):

  class SCResult():
    """ SubCompleter Result

    :param str candidate:       What will replace the line once it will be chosen
    :param str to_be_displayed: What will be displayed
    """
    @beartype
    def __init__(self, candidate: str, to_be_displayed: str):

      self.candidate = candidate
      self.to_be_displayed = to_be_displayed

    def __repr__(self):
      return f"SCResult('{self.candidate}','{self.to_be_displayed}')"

  @beartype
  def __init__(self):
    pass

  @abstractmethod
  @beartype
  def values(self, text: str) -> List[SCResult]:
    """  Compute candidates and displayed values regarding the line

    :param str line: List of candidates and displayed values
    """
    pass


class SubCompleterChildren(SubCompleter):

  @beartype
  def __init__(self, ods: "OneDriveShell", only_folder: bool):
    super(self.__class__, self).__init__()
    self.ods = ods
    self.__only_folder = only_folder

  @beartype
  def values(self, text: str) -> List[SubCompleter.SCResult]:
    parts_cmd = CommonCompleter.get_cmd_parts_with_quotation_guess(text)

    if len(parts_cmd) > 1:
      last_arg = parts_cmd[-1]
      was_relative_path = len(
          last_arg) > 0 and last_arg[0] != '/' or last_arg == ""

      # lfip = last_folder_info_path   -  rt = remaining test
      (lfip, rt) = MsObject.get_lastfolderinfo_path(
          self.ods.root_folder, last_arg, self.ods.current_fi)
      if lfip is None:  # Non existing folder
        return []
      start_text = rt
      folder_names_str = lfip.path + '/'
      if was_relative_path and folder_names_str.startswith(
              self.ods.current_fi.path):
        folder_names_str = folder_names_str[(
            len(self.ods.current_fi.path) + 1):]
      search_folder = lfip
    else:
      start_text = ""
      folder_names_str = ""
      search_folder = self.ods.current_fi

    # Extract start of last arguments to be escaped if necessary. Other
    # arguments won't be changed
    if len(parts_cmd) > 1:
      if parts_cmd[-1] != "":
        raw_last_arg = CommonCompleter.extract_raw_last_args(
            text, parts_cmd[-1])
        start_line = text[:-(len(raw_last_arg))]
      else:
        start_line = text
    else:  # len(parts_cmd) == 1
      start_line = text.rstrip() + " "

    new_start_line = start_line + StrPathUtil.escape_str(folder_names_str)

    # Compute list of substitute string
    #   1. Compute folder names
    #   2. Append '/' to all folders
    #   3. Keep folders whose name starts with start_text
    #   4. Add escaped folder name
    search_folder.retrieve_children_info()
    if self.__only_folder:
      all_children = search_folder.children_folder
    else:
      all_children = (search_folder.children_folder
                      + search_folder.children_file
                      + search_folder.children_other)
    folders = map(
        lambda x: f"{x.name}{'/' if isinstance(x, MsFolderInfo) else ''}",
        all_children)
    folders = filter(lambda x: x.startswith(start_text), folders)
    folders = map(lambda x: StrPathUtil.escape_str(x), folders)
    map_values = map(
        lambda x: SubCompleter.SCResult(
            f"{new_start_line}{x}", x), folders)
    list_values = list(map_values)
    return list_values


class SubCompleterLocalCommand(SubCompleter):
  """ SubCompleter for local command

    Based on the following snippets:
       https://gist.github.com/mkhon/ad39dd3e54dd783b63d4
  """
  RE_SPACE = re.compile('.*\\s+$', re.M)

  def __init__(self, custom_command=None, first_exclamation_mark=True):
    super(self.__class__, self).__init__()
    self.builtins = None
    self.commands = {}
    if custom_command is not None:
      self.commands[custom_command] = True
    self.cmd_lookup = None
    self.path_lookup = None
    self.__first_exclamation_mark = first_exclamation_mark

    # try to get shell builtins
    shell = os.environ.get('SHELL')
    if shell:
      p = subprocess.Popen([shell, '-c', 'compgen -b'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      out, err = p.communicate()
      self.builtins = dict((key.decode(), True) for key in out.split())
    if not self.builtins:
      self.builtins = {'cd': True}

  def _generate(self, prefix):
    def begins_with(s): return s[:len(prefix)] == prefix
    self.cmd_lookup = {}

    # append commands in PATH
    for path in map(os.path.expanduser, os.environ.get('PATH', '').split(':')):
      if not os.path.isdir(path):
        continue

      for f in filter(begins_with, os.listdir(path)):
        self.cmd_lookup[f] = True

    # append shell builtins
    for n in filter(begins_with, self.builtins.keys()):
      self.cmd_lookup[n] = self.builtins[n]

    # append COMMANDS
    for n in filter(begins_with, self.commands.keys()):
      self.cmd_lookup[n] = self.commands[n]
    # print "\nGenerated commands for prefix %s: %s" % (`prefix`,
    # `self.cmd_lookup`)

  def _listdir(self, root):
    "List directory 'root' appending the path separator to subdirs."
    res = []
    for name in os.listdir(root):
      path = os.path.join(root, name)
      if os.path.isdir(path):
        name += os.sep
      res.append(name)
    return res

  def _complete_path(self, path=None):
    "Perform completion of filesystem path."
    if not path:
      return self._listdir('.')
    dirname, rest = os.path.split(path)
    tmp = dirname if dirname else '.'
    res = [os.path.join(dirname, p)
           for p in self._listdir(tmp) if p.startswith(rest)]
    # more than one match, or single match which does not exist (typo)
    if len(res) > 1 or not os.path.exists(path):
      return res
    # resolved to a single directory, so return list of files below it
    if os.path.isdir(path):
      return [os.path.join(path, p) for p in self._listdir(path)]
    # exact file match terminates this completion
    return [path + ' ']

  def values(self, text: str) -> List[SubCompleter.SCResult]:
    "Generic readline completion entry point."

    try:
      # remove first '!'
      buffer = text[1:] if self.__first_exclamation_mark else text
      text_part = buffer.split()
      # account for last argument ending in a space
      if text_part and SubCompleterLocalCommand.RE_SPACE.match(buffer):
        text_part.append('')

      if len(text_part) == 0:
        return []
      last_arg = text_part[-1]
      # command completion
      first_char = "!" if self.__first_exclamation_mark else ""
      if len(text_part) < 2:
        self._generate(last_arg)
        result = [c + ' ' for c in self.cmd_lookup.keys()]
        return list(
            map(
                lambda x: SubCompleter.SCResult(
                    f"{first_char}{x}",
                    x),
                result))

      else:
        # check if we should do path completion
        start_line = ' '.join(text_part[:-1])
        cmd = text_part[0]
        if not self.cmd_lookup:
          self._generate(cmd)
        if cmd not in self.cmd_lookup or not self.cmd_lookup[cmd]:
          return []
        result = self._complete_path(os.path.expanduser(last_arg))
        result = map(lambda x: StrPathUtil.escape_str(x), result)
        return list(
            map(
                lambda x: SubCompleter.SCResult(
                    f"{first_char}{start_line} {x}",
                    x),
                result))

    except Exception as e:
      lg.error(f"[subCompleter shell]Error '{e}'")


class SubCompleterMulti(SubCompleter):

  @beartype
  def __init__(self, ods: "OneDriveShell", custom_command: str):
    super(self.__class__, self).__init__()
    self.__sc_first_arg = SubCompleterLocalCommand(
        custom_command=custom_command, first_exclamation_mark=False)
    self.__sc_second_arg = SubCompleterChildren(ods, False)
    self.lg_complete = logging.getLogger("odc.browser.completer")

  @beartype
  def values(self, text: str) -> List[SubCompleter.SCResult]:
    parts_cmd = CommonCompleter.get_cmd_parts_with_quotation_guess(text)
    self.lg_complete.debug(parts_cmd)
    if ((text[-1] == " " and len(parts_cmd) == 1)
            or (text[-1] != " " and len(parts_cmd) == 2)):
      return self.__sc_first_arg.values(text)
    elif ((text[-1] == " " and len(parts_cmd) == 2)
          or (text[-1] != " " and len(parts_cmd) == 3)):
      return self.__sc_second_arg.values(text)


class SubCompleterNone(SubCompleter):
  def __init__(self):
    pass

  @beartype
  def values(self, line: str) -> List[SubCompleter.SCResult]:
    return []


class Completer:
  """
  Everything is replaced in the readline buffer to managed folder name with space

   To avoid misunderstanding, only the folder name is displayed in the match list
  """

  def __init__(self, odshell: "OneDriveShell"):
    self.shell = odshell
    self.values = []
    self.start_line = ""
    self.new_start_line = ""
    self.columns_printer = ColumnsPrinter(2)
    self.lg_complete = logging.getLogger("odc.browser.completer")

  def __log_debug(self, what):
    self.lg_complete.debug(f"[complete]{what}")

  def display_matches(self, what, matches, longest_match_length):
    try:
      self.__log_debug(f"[display matches]dm('{what}',{matches})")
      print("")

      # remove start_line from matches and convert to FormattedString
      to_be_printed = list(
          map(
              lambda x: FormattedString.build_from_string(
                  x.to_be_displayed),
              self.values))
      self.columns_printer.print_with_columns(to_be_printed)
      print(
          f"{self.shell.get_prompt()}{readline.get_line_buffer()}",
          end="",
          flush=True)

    except Exception as e:
      print(f"Exception = {e}")

  @beartype
  def complete(self, text: str, state: int):

    self.__log_debug(f"complete('{text}',{state})")

    try:

      if state == 0:
        with self.shell.global_lock:
          parts_cmd = CommonCompleter.get_cmd_parts_with_quotation_guess(text)
          if len(parts_cmd) > 0 and (parts_cmd[0] in self.shell.dict_cmds):
            sub_completer = self.shell.dict_cmds[parts_cmd[0]].sub_completer
            self.values = sub_completer.values(text)

          elif len(parts_cmd) > 0 and parts_cmd[0][0] == "!":
            sub_completer = SubCompleterLocalCommand()
            self.values = sub_completer.values(text)

          else:
            self.values = []

      if state < len(self.values):
        self.__log_debug(f"  --> return {self.values[state]}")
        return self.values[state].candidate
      else:
        return None

    except Exception as e:
      print(f"[complete]Exception = {e}")
      if self.lg_complete.level >= logging.DEBUG:
          error_line = "stack trace :\n"
          for a in traceback.format_tb(e.__traceback__):  # Print traceback
            error_line += f"  {a}"
          self.__log_debug(error_line)


class DeltaChecker():

  def __init__(self, mgc: MsGraphClient):
    self.mgc = mgc
    query_string = (
        f"{MsGraphClient.graph_url}/me/drive/root/delta?token=latest")
    r = self.mgc.mgc.get(query_string)
    self.delta_link = r.json()["@odata.deltaLink"]

    self.items_to_be_processed = []
    self.lg = logging.getLogger("odc.browser.checkdelta")

  def get_diffs(self):
    query_string = self.delta_link
    i = 0
    while True:
      r = self.mgc.mgc.get(query_string)
      items_json = r.json()
      current_items_list = items_json['value']
      self.items_to_be_processed += current_items_list
      i = i + 1
      if "@odata.nextLink" in items_json:
        query_string = items_json["@odata.nextLink"]
      else:
        break
    self.delta_link = r.json()['@odata.deltaLink']

  def __process_diff_delete(self, diff_item):
    """
      If object exists, remove from child list and from global dictionary
    """
    msobj = DictMsObject.get(diff_item["id"])
    if msobj is not None:
      DictMsObject.remove(diff_item["id"])
      self.lg.debug(f"Remove object '{msobj.path}' from dict")
      msobj_parent = DictMsObject.get(diff_item["parentReference"]["id"])
      # and isinstance(msobj_new_parent, MsFolderInfo):
      if msobj_parent is not None:
        msobj_parent.remove_info_for_child(msobj)

  def __process_diff_file(self, diff_item):
    """
      Update file info related to diff_item only if it is already synchronized.
      Create file info if parent exists.
      Parent folder are not updated.
      self.__new_parent_to_be_processed is updated
    """
    # diff_item MUST be a file file item

    # 0 - Check that requisites are completed
    if self.lg.level >= logging.DEBUG:
      if "file" not in diff_item:
        self.lg.debug("__process_diff_file is invoked with a non-file Item")

    # 0.1 - Init
    msobj = DictMsObject.get(diff_item["id"])

    # 2 - Update new/updated items
    fi_ref = OIF.MsFileInfoFromMgcResponse(
        self.mgc, diff_item,
        no_warn_if_no_parent=True, no_update_and_get_from_global_dict=True)

    # 3 - Update file info if necessary and create it if parent exists
    parent_id = diff_item["parentReference"]["id"]
    msobj_new_parent = DictMsObject.get(parent_id)

    if msobj is not None:
      self.lg.debug(f"Known file has been updated - obj = {msobj.path}")
      OIF.UpdateMsFileInfo(msobj, fi_ref)

    if msobj is None and msobj_new_parent is not None:
      self.lg.debug(f"Unknown file but parent exists."
                    f"parent = {msobj_new_parent.path} ")
      msobj = fi_ref
      DictMsObject.add_or_get_update(msobj)

    if msobj is not None:
      self.__new_parentship_to_be_processed.append((msobj, msobj_new_parent))

  def __process_diff_folder(self, diff_item):
    """
      Update folder info related to diff_item only if it is already synchronized.
      Create folder info if parent exists.
      self.__new_parent_to_be_processed is updated
    """
    # diff_item MUST be a folder item

    # 0 - Check that requisites are completed
    if self.lg.level >= logging.DEBUG:
      if "folder" not in diff_item:
        self.lg.debug(
            "__process_diff_folder is invoked with a non-folder Item")

    self.lg.debug(f"process folder '{diff_item['name']}'")
    # 0.1 - Init
    msobj = DictMsObject.get(diff_item["id"])

    # 2 - Update new/updated items
    try:
      fi_ref = OIF.get_object_info_from_id(
          self.mgc, diff_item["id"], no_warn_if_no_parent=True,
          no_update_and_get_from_global_dict=True)
    except OIF.ObjectRetrievalException:
      self.lg.warning(f"No folder object found '{diff_item['name']}'")
      return

    # 3 - Update folder info if necessary and create it if parent exists
    if msobj is not None:
      self.lg.debug(f"Known folder has been updated - obj = {msobj.path}")
      OIF.UpdateMsFolderInfo(msobj, fi_ref)

    # 4 - Update parent if msobj is not root
    if 'root' in diff_item:
      # Delta item received for root folder. Skip parent update
      return

    parent_id = diff_item["parentReference"]["id"]
    msobj_new_parent = DictMsObject.get(parent_id)
    if msobj is None and msobj_new_parent is not None:
      self.lg.debug(f"Unknown folder but parent exists."
                    f"parent = {msobj_new_parent.path}")
      msobj = fi_ref
      DictMsObject.add_or_get_update(msobj)

    if msobj is not None:
      self.__new_parentship_to_be_processed.append((msobj, msobj_new_parent))

  @beartype
  def __process_parentship(
          self,
          parentship_item: Tuple[MsObject, Optional[MsObject]]):

    (msobj, new_parent) = parentship_item
    self.lg.debug(f"process_parentship with obj {msobj.name}")
    if new_parent is None:  # parent is not cached
      # Remove object from previous item
      if not msobj.is_root:
        msobj.parent.remove_info_for_child(msobj)
        DictMsObject.remove(msobj.ms_id)

    elif msobj.parent is None:
      msobj.update_parent(new_parent)
      new_parent.add_object_info(msobj)

    elif msobj.parent.ms_id != new_parent.ms_id:
      msobj.parent.remove_info_for_child(msobj)
      msobj.update_parent(new_parent)
      new_parent.add_object_info(msobj)

  def process_diffs(self):
    # Noted on December 12, 2024
    #
    #  - When a file is created or modified delta is received for new file and all ascendant folders
    #  - When a file is deleted, delta item contains file info about file deleted and delta for root
    #  - In any case, folder information (size and nb of children) is updated a few minutes later
    self.lg.debug(f"items_to_be_process = {self.items_to_be_processed}")
    deleted_item_to_be_processed = list(
        filter(lambda x: "deleted" in x, self.items_to_be_processed))
    folders_to_be_processed = list(
        filter(lambda x: "folder" in x and "deleted" not in x,
               self.items_to_be_processed))
    files_to_be_processed = list(
        filter(lambda x: "file" in x and "deleted" not in x,
               self.items_to_be_processed))
    self.lg.debug(f"nb deleted = {len(deleted_item_to_be_processed)}. "
                  f"nb folders = {len(folders_to_be_processed)}. "
                  f"nb files = {len(files_to_be_processed)}")
    # list of tuple of (msobj, new_parent_obj)
    self.__new_parentship_to_be_processed = []
    list(map(self.__process_diff_delete, deleted_item_to_be_processed))
    list(map(self.__process_diff_file, files_to_be_processed))
    list(map(self.__process_diff_folder, folders_to_be_processed))
    list(map(self.__process_parentship, self.__new_parentship_to_be_processed))
    self.__new_parentship_to_be_processed = None

  def reinit(self):
    self.items_to_be_processed = []


class ServerCheckDelta():

  class EMA():
    """
    Exponential Moving Average related to ticks

    It will be used to compute delay between two pulls
    launched by the server. One tick will match with a OneDrive command.
    """

    def __init__(self, lg=None):
      self.__last_tick = time.time()
      self.__alpha = 0.3
      self.__value = 15  # seconds
      self.lg = lg

    def tick(self):
      old_last_tick = self.__last_tick
      self.__last_tick = time.time()
      delay_since_last_tick = self.__last_tick - old_last_tick
      self.__value = (delay_since_last_tick * self.__alpha
                      + self.__value * (1 - self.__alpha))

    def value_if_ticked_now(self):
      delay_since_last_tick = time.time() - self.__last_tick
      result = (delay_since_last_tick * self.__alpha
                + self.__value * (1 - self.__alpha))
      if self.lg is not None:
        self.lg.debug(
            f"delay_since_last_tick={delay_since_last_tick:.3f}"
            f"- value={self.__value:.3f} - value_if_ticked_now={result:.3f}")
      return result

    @property
    def value(self):
      return self.__value

  def __init__(self, mgc: MsGraphClient, lock_process: Lock):
    self.counter = 0
    self.to_be_stopped = Event()
    self.is_stopped = Event()
    self.mgc = mgc
    self.lg = logging.getLogger("odc.browser.checkdelta")
    self.dc = DeltaChecker(mgc)

    self.__ema = self.__class__.EMA()
    self.__min_wait_delay = 15  # seconds
    self.__max_wait_delay = 5 * 60  # 5 minutes
    self.__wait_delay = 20.0  # starting waiting delay
    self.__coef_delay = 2  # new wait delay will be ema * coef

    self.__lock_process = lock_process

  def loop(self):
    while True:
      self.lg.debug(f"start delta processing - {self.counter}")
      try:
        with self.__lock_process:
          self.dc.get_diffs()
          # self.dc.print_last_diffs()
          if len(self.dc.items_to_be_processed) > 0:
            self.dc.process_diffs()
      except Exception as e:
        self.lg.error(f"Error during processing diff: {e}")
        if self.lg.level >= logging.DEBUG:
          error_line = "stack trace :\n"
          for a in traceback.format_tb(e.__traceback__):  # Print traceback
            error_line += f"  {a}"
          self.lg.debug(error_line)
      self.dc.reinit()
      self.lg.debug(f"end delta processing - {self.counter}"
                    f" - wait {self.__wait_delay:.1f} seconds")

      self.counter += 1
      if self.to_be_stopped.wait(timeout=self.__wait_delay):
        break

      self.update_delay_with_ema_value(self.__ema.value_if_ticked_now())

    self.lg.debug("loop is stopped")
    self.is_stopped.set()

  def tick(self):
    self.__ema.tick()
    self.update_delay_with_ema_value(self.__ema.value)

  def update_delay_with_ema_value(self, ema_value):
    theoretical_delay = ema_value * self.__coef_delay
    if theoretical_delay < self.__min_wait_delay:
      self.__wait_delay = self.__min_wait_delay
    elif theoretical_delay > self.__max_wait_delay:
      self.__wait_delay = self.__max_wait_delay
    else:
      self.__wait_delay = theoretical_delay
    self.lg.debug(
        f"new wait delay={self.__wait_delay:.1f} - ema_value={ema_value:.1f}")

  def stop(self):
    self.to_be_stopped.set()
    self.is_stopped.wait(timeout=5)


class OneDriveShell:

  class ArgumentParserWithoutExit(argparse.ArgumentParser):
    """
      ArgumentParser without exiting on error.
    """

    def exit(self, status=0, message=None):
      lg.debug(
          f"Should exit with status '{status}' according to ArgumentParser original method.")

    def error(self, message):
      self.print_usage(sys.stderr)
      raise ValueError(message)

  # TODO Add aliases possibility
  # TODO Keep previous history when relaunching the shell
  # TODO Remember configuration in a file
  # TODO Emphasize shell output by avoiding print command

  class Command(ABC):

    @beartype
    def __init__(
            self,
            name: str,
            my_argparser: argparse.ArgumentParser,
            sub_completer: SubCompleter):
      self.name = name
      self.argp = my_argparser
      self.sub_completer = sub_completer

    @beartype
    @abstractmethod
    def _do_action(self, args):  # Protected method
      pass

    def do_action(self, args):   # Public method
      self._do_action(args)

  @beartype
  def __init__(self, mgc: MsGraphClient):
    cinit()  # initialize colorama
    self.mgc = mgc
    self.root_folder = OIF.get_object_info_from_path(
        mgc, "/", no_warn_if_no_parent=True)
    # Ensure that root is a MsFolderInfo object
    # Only for help development with autocompletion
    if not isinstance(self.root_folder, MsFolderInfo):
      return
    self.current_fi = self.root_folder
    self.ls_formatter = LsFormatter(
        MsNoFolderFormatter(20),
        MsFolderFormatter(20))
    self.cp = Completer(self)
    self.initiate_commands()
    # Lock to ensure no simultaneousity of command launch, completion and
    # delta checking
    self.global_lock = Lock()
    self.scd = ServerCheckDelta(self.mgc, self.global_lock)

  def initiate_commands(self):

    # Methods to buil commands
    def init_with_odshell(self2, name, my_argparser, sub_completer):
      super(self2.__class__, self2).__init__(name, my_argparser, sub_completer)

    def add_new_cmd(name, my_argparser, doa, sub_completer):
      new_class = type(f"Class_{name}", (OneDriveShell.Command, ), {
          "__init__": init_with_odshell,
          "_do_action": doa
      })
      self.dict_cmds[name] = new_class(name, my_argparser, sub_completer)

    # Actions of commands

    def action_cd(self2, args):
      self.change_to_path(args.path)

    def action_ls(self2, args):
      errors = []
      paths_to_be_listed = []

      # Compute paths and errors
      for path in args.path:
        (lfip, rt_path) = MsObject.get_lastfolderinfo_path(
            self.root_folder, path, self.current_fi)
        if lfip is None:
          errors.append(f"'{path}' not found")
        else:
          if lfip.relative_path_is_a_folder(rt_path, True):
            paths_to_be_listed.append(lfip.get_child_folder(rt_path))
          elif lfip.relative_path_is_a_file(rt_path, True):
            errors.append(f"'{path}' is a file. No listing available.")
          else:
            errors.append(f"'{path}' not found.")

      # Print errors
      list(map(lambda x: print(x), errors))

      # Print paths
      lines_to_be_printed = []
      for fi in paths_to_be_listed:
        if len(paths_to_be_listed) > 1:
          lines_to_be_printed.append("")
          lines_to_be_printed.append(f"{fi.path}/:")
        str_folder_children = (
            self.ls_formatter.format_folder_children_lite(
                fi,
                recursive=args.r,
                depth=args.d,
                max_retrieved_children=args.maxchildren) if not args.l else self.ls_formatter.format_folder_children_long(
                    fi,
                    recursive=args.r, depth=args.d,
                    max_retrieved_children=args.maxchildren))

        lines_to_be_printed.append(str_folder_children)
      str_to_be_printed = '\n'.join(lines_to_be_printed)
      print_with_optional_paging(str_to_be_printed, args.p)

    def action_lls(self2, args):
      self.ls_formatter.print_folder_children_lite_next(
          self.current_fi)

    def action_stat(self2, args):
      obj_name = args.remotepath
      cfi = self.current_fi
      # if not isinstance(cfi, MsFolderInfo):
      #   return
      if cfi.relative_path_is_a_file(
              obj_name, force_children_retrieval=True):
        print(cfi.get_child_file(obj_name).str_full_details())
      elif cfi.relative_path_is_a_folder(obj_name):
        print(cfi.get_child_folder(obj_name).str_full_details())
      elif cfi.relative_path_is_other(obj_name):
        print(cfi.get_child_other(obj_name).str_full_details())
      else:
        print(f"{obj_name} is not a child of current folder({cfi.path})")

    def action_get(self2, args):
      file_name = args.remotepath
      if self.current_fi.relative_path_is_a_file(file_name):
        self.mgc.download_file_content_from_path(
            self.current_fi.get_child_file(file_name).path, os.getcwd())
      else:
        print(f"{file_name} is not a file of current folder({self.current_fi.path})")

    def action_put(self2, args):

      src_filename = os.path.split(args.srcfile)[1]

      # Compute dst_folder_path and dst_filename
      (lfip_dst, rt_dst) = MsObject.get_lastfolderinfo_path(
          self.root_folder, args.dstpath, self.current_fi)

      if lfip_dst is None:
        print("destination folder not found")
        return False
      if lfip_dst.relative_path_is_a_folder(rt_dst, True):

        dst_parent = lfip_dst.get_child_folder(rt_dst)
        if dst_parent.relative_path_is_a_file(src_filename):
          print(f"{dst_parent.path}/{src_filename} already exists."
                f" Remove it before upload")
          return False
        dst_folder_path = os.path.normpath(dst_parent.path)
        dst_filename = src_filename

      elif lfip_dst.relative_path_is_a_file(rt_dst, True):
        print(f"{rt_dst} is a file. Remove it before upload.")
        return False
      else:
        dst_parent = lfip_dst
        dst_folder_path = os.path.normpath(lfip_dst.path)
        dst_filename = rt_dst

      self.mgc.put_file_content_from_fullpath_of_dstfolder(dst_folder_path, args.srcfile, dst_filename)

      msoi_new_file = OIF.get_object_info_from_path(
          self.mgc, f"{dst_folder_path}/{dst_filename}", parent=dst_parent)[1]
      msoi_new_file.update_parent_after_arrival(
          dst_parent, msoi_new_file.last_modified_datetime)
      return True

    def action_mv(self2, args):
      # lfip = last_folder_info_path
      # rt = remaining_text

      # Compute source path
      (lfip_src, rt_src) = MsObject.get_lastfolderinfo_path(
          self.root_folder, args.srcpath, self.current_fi)
      if lfip_src is None:
        print("source folder not found")
        return False
      if lfip_src.relative_path_is_a_file(rt_src, True):
        src_obj = lfip_src.get_child_file(rt_src)
      elif lfip_src.relative_path_is_a_folder(rt_src, True):
        src_obj = lfip_src.get_child_folder(rt_src)
      else:
        print(f"'{args.srcpath}' is not a path of a remote object")
        return False

      # Compute dest path
      (lfip_dst, rt_dst) = MsObject.get_lastfolderinfo_path(
          self.root_folder, args.dstpath, self.current_fi)
      if lfip_dst is None:
        print("source folder not found")
        return False
      if lfip_dst.relative_path_is_a_folder(rt_dst, True):
        is_a_renaming = False
        dst_parent = lfip_dst.get_child_folder(rt_dst)
        dst_path2 = os.path.normpath(
            f"{dst_parent.path}/{rt_src}")
      elif lfip_dst.relative_path_is_a_file(rt_dst, True):
        return False
      else:
        is_a_renaming = True
        new_name = rt_dst
        dst_parent = lfip_dst
        dst_path2 = os.path.normpath(f"{lfip_dst.path}/{rt_dst}")

      lg.debug(f"move('{src_obj.path}','{dst_path2}')")

      r = self.mgc.move_object(src_obj.path, dst_path2)
      if not r:
        print(f"[Move]An error has occured")
        return False
      if is_a_renaming:
        src_obj.rename(new_name)
      src_obj.move_object(dst_parent)
      return True

    def action_mkdir(self2, args):

      # Compute dest path
      (lfip_dst, rt_dst) = MsObject.get_lastfolderinfo_path(
          self.root_folder, args.dstpath, self.current_fi)
      if lfip_dst is None:
        print("destination folder not found")
        return False
      if lfip_dst.relative_path_is_a_folder(rt_dst, True):
        dst_parent = lfip_dst.get_child_folder(rt_dst)
        folder_name = rt_dst
      elif lfip_dst.relative_path_is_a_file(rt_dst, True):
        print(f"'{args.dstpath} exists and is a file.")
        return False
      else:
        dst_parent = lfip_dst
        folder_name = rt_dst

      msoi_newfolder = dst_parent.create_empty_subfolder(folder_name)
      return msoi_newfolder is not None

    def action_rm(self2, args):
      (lfip_dst, rt_dst) = MsObject.get_lastfolderinfo_path(
          self.root_folder, args.dstpath, self.current_fi)
      if lfip_dst.relative_path_is_a_file(rt_dst, True):
        dst_obj = lfip_dst.get_child_file(rt_dst)
      elif lfip_dst.relative_path_is_a_folder(rt_dst, True):
        dst_obj = lfip_dst.get_child_folder(rt_dst)
      else:
        print(f"'{args.dstpath}' is not a path of a remote object")
        return False
      dst_path = os.path.normpath(f"{lfip_dst.path}/{rt_dst}")
      r = self.mgc.delete_file(dst_path)
      if r != 1:
        print("[rm]An error has occured")
        return False
      dst_obj.update_parent_before_removal()
      DictMsObject.remove(dst_obj.ms_id)
      return True

    def action_pwd(self2, args):
      print(self.current_fi.path)

    def action_l_cd(self2, args):
      os.chdir(args.path)
      print(os.getcwd())

    # Arguments management
    myparser = OneDriveShell.ArgumentParserWithoutExit(
        prog='Onedrive Shell', usage='')

    # myparser.add_argument('num', type=int, help='num', nargs='?',default=None)
    sub_parser = myparser.add_subparsers(dest='cmd')
    sp_cd = sub_parser.add_parser('cd', description='Change directory')
    sp_cd.add_argument('path', type=str, help='Destination path')
    sp_ls = sub_parser.add_parser(
        'ls', description='List current folder by column')
    sp_ls.add_argument(
        '-p',
        action='store_true',
        default=False,
        help='Enable pagination')
    sp_ls.add_argument(
        '-l',
        action='store_true',
        default=False,
        help='Add details to file and folders'
    )
    sp_ls.add_argument(
      '--maxchildren',
      '-n',
      type=int,
      default=200,
      help='Max number retrieved children. The next multiple of 200 will be considered. Default 200')
    sp_ls.add_argument(
        '-r',
        action='store_true',
        default=False,
        help='Recursive listing')
    sp_ls.add_argument(
        '-d',
        type=int,
        default=1,
        help='Recursion depth (Default=1)')
    sp_ls.add_argument(
        'path',
        type=str,
        help='Path of folder',
        nargs='*',
        default='.')
    sp_lls = sub_parser.add_parser(
        'lls', description='Continue listing folder in case of large folder')
    sp_pwd = sub_parser.add_parser(
        'pwd', description='Print full path of current folder')
    sp_get = sub_parser.add_parser(
        'get', description='Download file in current folder')
    sp_get.add_argument('remotepath', type=str, help='remote file')
    sp_put = sub_parser.add_parser(
        'put', description='Upload a file')
    sp_put.add_argument('srcfile', type=str, help='source file')
    sp_put.add_argument('dstpath', type=str, help='destination path')
    sp_rm = sub_parser.add_parser(
        'rm', description='Remove a file or a folder')
    sp_rm.add_argument(
        'dstpath',
        type=str,
        help='File or Folder to be removed')
    sp_mv = sub_parser.add_parser(
        'mv', description='Move or rename a file or a folder')
    sp_mv.add_argument(
        'srcpath',
        type=str,
        help='Path of the remote file or folder')
    sp_mv.add_argument(
        'dstpath',
        type=str,
        help='Destination path of file or folder')
    sp_stat = sub_parser.add_parser(
        'stat', description='Get info about object')
    sp_stat.add_argument('remotepath', type=str, help='destination object')
    sp_mkdir = sub_parser.add_parser('mkdir', description='Make a folder')
    sp_mkdir.add_argument('dstpath', type=str, help='path of new folder')
    sp_l_cd = sub_parser.add_parser('!cd', description="Change local folder")
    sp_l_cd.add_argument('path', type=str, help='Destination path')

    # (*) https://bugs.python.org/issue9334#msg169712

    self.__args_parser = myparser

    # Populate commands
    self.dict_cmds: dict[str, OneDriveShell.Command] = {}
    add_new_cmd('cd', sp_cd, action_cd, SubCompleterChildren(
        self, only_folder=True))
    add_new_cmd('ls', sp_ls, action_ls, SubCompleterChildren(
        self, only_folder=True))
    add_new_cmd('lls', sp_lls, action_lls, SubCompleterNone())
    add_new_cmd('stat', sp_stat, action_stat, SubCompleterChildren(
        self, only_folder=False))
    add_new_cmd('mkdir', sp_mkdir, action_mkdir, SubCompleterChildren(
        self, only_folder=True))
    add_new_cmd('get', sp_get, action_get, SubCompleterChildren(
        self, only_folder=False))
    add_new_cmd('put', sp_put, action_put, SubCompleterMulti(self, 'put'))
    add_new_cmd('mv', sp_mv, action_mv, SubCompleterChildren(
        self, only_folder=False))
    add_new_cmd('rm', sp_rm, action_rm, SubCompleterChildren(
        self, only_folder=False))
    add_new_cmd('pwd', sp_pwd, action_pwd, SubCompleterNone())
    # For any strange reason, cd does not work as common 'os.system'
    add_new_cmd('!cd', sp_l_cd, action_l_cd, SubCompleterLocalCommand())

  def change_max_column_size(self, nb):
    self.ls_formatter = LsFormatter(
        MsNoFolderFormatter(nb),
        MsFolderFormatter(nb))

  def change_current_folder_to_parent(self):
    if self.current_fi.parent is not None:
      self.current_fi = self.current_fi.parent
    else:
      print("The current folder has no parent")

  def get_prompt(self):
    result = self.current_fi.name
    if self.current_fi.next_link_children is not None:
      result += "..."
    result += "> "
    return result

  def launch_delta_server(self):
    thread_scd = Thread(target=self.scd.loop, daemon=True)
    thread_scd.start()

  def stop_delta_server(self):
    self.scd.stop()

  def launch(self):
    self.launch_delta_server()
    readline.parse_and_bind('tab: complete')
    readline.set_completer(self.cp.complete)
    if sys.platform != "win32":
      readline.set_completion_display_matches_hook(self.cp.display_matches)
    # All line content will be managed by complemtion
    readline.set_completer_delims("")

    self.current_fi.retrieve_children_info(recursive=False)

    print(get_versionned_name())
    print('Type "help" or "license" for more information')
    while True:

      my_raw_input = input(f"{self.get_prompt()}")
      # Trim my_input and remove double spaces
      my_input = " ".join(my_raw_input.split())
      my_input = my_input.replace(" = ", "=")
      try:
        parts_cmd = shlex.split(my_input)
      except ValueError as e:
        print(f"ERROR: {e}")
        parts_cmd = []
      if len(parts_cmd) > 0:
        cmd = parts_cmd[0]
      else:
        cmd = ""

      if cmd in ("q", "quit", "exit"):
        break

      if cmd == "":
        pass

      elif cmd in self.dict_cmds:
        args = []
        try:
          args = self.__args_parser.parse_args(parts_cmd)
          with self.global_lock:
            self.dict_cmds[cmd].do_action(args)
          self.scd.tick()
        except Exception as e:
          print(f"error: {e}")
          if lg.level >= logging.DEBUG:
            lg.error(f"Shell error: {e} - Command = {cmd}")
            error_line = "stack trace :\n"
            for a in traceback.format_tb(e.__traceback__):  # Print traceback
              error_line += f"  {a}"
            lg.debug(error_line)

      elif cmd[0] == "!":
        os.system(my_raw_input[1:])

      elif cmd == "cd..":
        self.change_current_folder_to_parent()

      elif my_input[:7] == "set cs=" or my_input[:15] == "set columnsize=":
        str_cs = my_input[7:] if my_input[:7] == "set cs=" else my_input[15:]

        if not str_cs.isdigit():
          print("<value> of column size must be a digit")
        else:
          int_cs = int(str_cs)
          if (int_cs < 5) or (int_cs > 300):
            print("<value> must be a number between 5 and 300")
          else:
            self.change_max_column_size(int_cs)

      elif cmd == "help" or cmd == "h":
        if len(parts_cmd) == 1:
          print(get_versionned_name())
          print("")
          print("Available commands")
          for (k, v) in self.dict_cmds.items():
            print(f"  {k:20}{v.argp.description}")

          print(f"  {'!<shell_command>':20}Launch local shell command")
          print(f"  {'set':20}Set a variable")
          print()
          print(f"  {'help/h':20}Print this help message")
          print(f"  {'license':20}Print license")
          print(f"  {'q/quit/exit':20}Quit the shell")
          print("")
          print(f"{PROGRAM_NAME} is also available as command line program.")
          print(f"Launch it with '-h' parameter for more information.")

        elif len(parts_cmd) == 2:
          if parts_cmd[1] in self.dict_cmds:
            self.dict_cmds[parts_cmd[1]].argp.print_help()
          elif parts_cmd[1] == "set":
            print("usage:")
            print("   set ( (<variable>|no<variable) | ( <variable>=<value> )")
            print()
            print("Variables that can be set and their aliases")
            print(
                "    columnsize/cs       int           Column Size of folder names and files names")
            print("                                      for long listing")

      elif cmd == "license":
        try:
          license_filename = f"{os.path.dirname(os.path.realpath(__file__))}{os.sep}..{os.sep}LICENSE"
          with open(license_filename, "r") as f:
            l_content = f.read()
            print(l_content)
        except Exception:
          print(f"Error while reading license.")
          print(f"Please ensure that your copy of {PROGRAM_NAME} is complete.")

      else:
        print("unknown command")

    self.stop_delta_server()

  def full_path_from_root_folder(self, str_path):
    """
       Build full path of an object from string given in command line.
       If str_path starts with a separator, path from root_path is computed.
       Else path from current_folder is considered
    """
    if str_path[0] != '/':
      result = os.path.normpath(self.current_fi.path + '/' + str_path)[1:]
    else:
      result = os.path.normpath(str_path[1:])
    return result

  def change_to_path(self, folder_path):

    # Compute relative path from root_folder
    full_path = self.full_path_from_root_folder(folder_path)

    if self.root_folder.relative_path_is_a_folder(
            full_path, force_children_retrieval=True):
      self.current_fi = self.root_folder.get_child_folder(full_path)


class InfoFormatter(ABC):

  @abstractmethod
  def format(self, what):
    return "default"

  @abstractmethod
  def format_lite(self, what):
    return "default"

  @staticmethod
  def format_last_modified_datetime(msoi: MsObject)->str:
    fmdt = msoi.last_modified_datetime
    delta = dt.now() - fmdt.replace(tzinfo=None)
    if delta.days > 6 * 30: # ~6 months
      result = fmdt.strftime(f"%b %d ") + f"{fmdt.year: >5}"
    else:
      result = fmdt.strftime("%b %d %H:%M")
    return result

class MsFolderFormatter(InfoFormatter):

  def __init__(self, max_name_size=25):
    self.max_name_size = max_name_size

  @beartype
  def format(self, what: MsFolderInfo):
    status_children = "<children ok>" if what.children_retrieval_is_completed() else ""

    fmdt = InfoFormatter.format_last_modified_datetime(what)

    if len(what.name) < self.max_name_size:
      fname = FormattedString.build_from_colorized_string(
          f"{Fore.BLUE}{Style.BRIGHT}{what.name}{Style.RESET_ALL}/",
          f"{what.name}/")
    else:
      fname = FormattedString.build_from_colorized_string(
          f"{Fore.BLUE}{Style.BRIGHT}{what.name[:self.max_name_size - 5]}{Style.RESET_ALL}.../",
          f"{what.name[:self.max_name_size - 5]}.../")

    result = FormattedString.concat(
        f"{what.size:>12}  {fmdt}  ",
        alignleft(
            fname,
            self.max_name_size),
        f"{what.child_count:>6}  {status_children}").rstrip()
    return result

  @beartype
  def format_lite(self, what: MsFolderInfo):
    return FormattedString.build_from_colorized_string(
        f"{Fore.BLUE}{Style.BRIGHT}{what.name}{Style.RESET_ALL}/",
        f"{what.name}/")


class MsNoFolderFormatter(InfoFormatter):
  def __init__(self, max_name_size=25):
    self.max_name_size = max_name_size

  @beartype
  def format(self, what: MsObject):
    fname = f"{what.name}" if len(
        what.name) < self.max_name_size else f"{what.name[:self.max_name_size - 5]}..."
    fmdt = InfoFormatter.format_last_modified_datetime(what)
    result = FormattedString.concat(
        f"{what.size:>12}  {fmdt}  ",
        alignleft(
            FormattedString.build_from_string(fname),
            self.max_name_size)).rstrip()
    return result

  @beartype
  def format_lite(self, what: MsObject):
    return FormattedString.build_from_string(what.name)


class LsFormatter():

  @beartype
  def __init__(
          self,
          file_formatter: MsNoFolderFormatter,
          folder_formatter: MsFolderFormatter,
          include_number: bool = True):
    self.file_formatter = file_formatter
    self.folder_formatter = folder_formatter
    self.column_printer = ColumnsPrinter(2)
    self.include_number = include_number

  @beartype
  def __format_folder_children(
          self,
          fi: MsFolderInfo,
          with_columns: bool,
          folder_desc_formatter,
          file_desc_formatter,
          recursive: bool = False,
          depth: int = 999,
          is_first_folder: bool = False,
          max_retrieved_children: int = 200) -> str:
    # A header with the folder path is added to each children
    # The same header is added if is_first_folder is True

    lg.debug(
        f"Entering __format_folder_children_lite({fi.path},"
        f"{recursive}, {depth}, {max_retrieved_children})")
    if not fi.children_retrieval_is_completed():
      fi.retrieve_children_info(max_retrieved_children=max_retrieved_children)

    folder_names = map(folder_desc_formatter, fi.children_folder)
    file_names = map(file_desc_formatter, fi.children_file)
    other_names = map(file_desc_formatter, fi.children_other)
    all_names = list(folder_names) + list(file_names) + list(other_names)

    if with_columns:
      result = self.column_printer.format_with_columns(all_names)
    else:
      result = '\n'.join(list(map(lambda x: x.to_be_printed, all_names)))

    if recursive and depth > 0 and len(fi.children_folder) > 0:
      if is_first_folder:
        result = f"{fi.path}/:\n" + result

      result += "\n"

      for child_folder in fi.children_folder:
        result += f"\n{child_folder.path}/:\n"
        result += self.__format_folder_children(
            child_folder,
            with_columns,
            folder_desc_formatter,
            file_desc_formatter,
            True,
            depth - 1,
            is_first_folder=False,
            max_retrieved_children=max_retrieved_children)
        result += "\n"

      result = result[:-1]
    return result

  @beartype
  def format_folder_children_long(
          self,
          fi: MsFolderInfo,
          recursive: bool = False,
          depth: int = 999,
          max_retrieved_children: int = 200) -> str:
    return self.__format_folder_children(
        fi, False,
        self.folder_formatter.format, self.file_formatter.format, recursive,
        depth, True, max_retrieved_children = max_retrieved_children
    )

  @beartype
  def print_folder_children_long(
          self,
          fi: MsFolderInfo,
          recursive: bool = False,
          depth: int = 999,
          with_pagination: bool = False,
          max_retrieved_children: int = 200) -> None:
    str_to_be_printed = self.format_folder_children_long(
        fi, recursive, depth, max_retrieved_children = max_retrieved_children)
    print_with_optional_paging(str_to_be_printed, with_pagination)

  @beartype
  def format_folder_children_lite(
          self,
          fi: MsFolderInfo,
          recursive: bool = False,
          depth: int = 999,
          max_retrieved_children: int = 200) -> str:
    lg.debug(
        f"Entering format_folder_children_lite({fi.path},"
        f"{recursive}, {depth}, {max_retrieved_children})")

    result = self.__format_folder_children(
        fi, True,
        self.folder_formatter.format_lite, self.file_formatter.format_lite,
        recursive, depth, is_first_folder=True,
        max_retrieved_children=max_retrieved_children)

    return result

  @beartype
  def print_folder_children_lite(
          self,
          fi: MsFolderInfo,
          with_pagination: bool = False,
          recursive: bool = False,
          max_retrieved_children: int = 200):

    str_to_be_printed = self.format_folder_children_lite(
        fi, recursive, 1,
        max_retrieved_children = max_retrieved_children)
    print_with_optional_paging(str_to_be_printed, with_pagination)

  @beartype
  def print_folder_children_lite_next(
          self, fi: MsFolderInfo):
    if (not fi.children_retrieval_is_completed()):
      fi.retrieve_children_info_next()

    self.print_folder_children_lite(fi)
