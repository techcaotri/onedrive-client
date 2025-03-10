#  Copyright 2019-2025 Jareth Lomson <jareth.lomson@gmail.com>
#  This file is part of OneDrive Client Program which is released under MIT License
#  See file LICENSE for full license details
import datetime
import logging
import math
import os
import sys
import urllib.parse
from abc import ABC, abstractmethod
from beartype import beartype
from lib._typing import Optional, Tuple
from lib.graph_helper import MsGraphClient, MsGraphException
from lib.datetime_helper import utc_dt_from_str_ms_datetime, utc_dt_now
from lib.strpathutil import StrPathUtil
from pathlib import PurePosixPath
from threading import Lock


lg = logging.getLogger('odc.msobject')


class MsObject(ABC):

  @beartype
  def __init__(
          self,
          parent: Optional["MsFolderInfo"],
          name: str,
          parent_path: str,
          ms_id: str,
          size: int,
          lmdt: datetime.datetime,
          cdt: datetime.datetime,
          is_root: bool = False):
    # Parent stat must not been updated if parent has just been initiated through mgc_response:
    #   - mgc_response contains child count, size but not all children
    self.ms_id = ms_id  # id is a keyword in python
    self.__size = size
    self.__parent = parent
    self.__name = name
    self.__parent_path = parent_path
    self.creation_datetime = cdt
    self.last_modified_datetime = lmdt
    self.is_root = is_root  # used to compute path

  @property
  def path(self):
    if self.__parent_path is None and self.parent is not None:
      # No parent path where parent exists.
      # Could be possible when new object has been detected without being
      # created through the shell
      if lg.level >= logging.DEBUG:
        lg.debug(f"path is invoked for {self.__name} whereas parent path"
                 f" does not exists. Create it")
      self.__parent_path = self.parent.path
    elif (lg.level >= logging.DEBUG
          and self.__parent_path is None and self.parent is None):
      lg.debug(f"path is invoked for {self.__name} whereas parent"
               f"is None. An exception will be probably raised")
    return "" if self.is_root else f"{self.__parent_path}/{self.__name}"

  @property
  def parent_path(self):
    return self.__parent_path

  @property
  def parent(self):
    return self.__parent

  @property
  def name(self):
    return self.__name

  @abstractmethod
  def _change_name_in_parent(self, name):
    pass

  def set_name(self, new_name):
    if self.name != new_name:
      self._change_name_in_parent(new_name)
      self.__name = new_name

  @property
  def size(self):
    return self.__size

  def set_size(self, size):
    self.__size = size

  @abstractmethod
  def str_full_details(self):
    pass

  def update_parent(self, new_parent):
    self.__parent = new_parent
    self.__parent_path = self.parent.path

  @property
  def __isabstractmethod__(self):
    return any(getattr(f, '__isabstractmethod__', False) for
               f in (self._fget, self._fset, self._fdel))

  def update_parent_before_removal(self, lmdt=None):
    if self.parent is None:
      return
    if lmdt is None:
      lmdt = utc_dt_now()
    self.parent.child_count -= 1

    current_parent = self.parent
    while current_parent is not None:
      current_parent.__size -= self.size
      current_parent.last_modified_datetime = lmdt
      current_parent = current_parent.parent

    self.parent.remove_info_for_child(self)

  @beartype
  def update_parent_after_arrival(self,
                                  new_parent: Optional["MsFolderInfo"],
                                  lmdt=Optional[datetime.datetime]):
    if new_parent is None:
      return
    if lmdt is None:
      lmdt = utc_dt_now()
    new_parent.child_count += 1
    current_parent = new_parent
    while current_parent is not None:
      current_parent.__size += self.__size
      current_parent.last_modified_datetime = lmdt
      current_parent = current_parent.parent
    new_parent.add_object_info(self)

  @beartype
  def move_object(self, new_parent: "MsFolderInfo",
                  lmdt: Optional[datetime.datetime] = None):
    self.update_parent_before_removal()
    self.update_parent(new_parent)
    self.__parent_path = new_parent.path
    self.update_parent_after_arrival(new_parent, lmdt)

  @beartype
  def rename(self, new_name: str):
    self.update_parent_before_removal()
    self.__name = new_name
    self.update_parent_after_arrival(self.parent)

  @staticmethod
  def get_lastfolderinfo_path(
          root_fi, input, current_fi=None) -> Tuple[Optional["MsFolderInfo"], Optional[str]]:
    """
      Return a tuple (<last_folder_info_path>, <remaining_text>)
    """
    my_input = input

    # Manage empty path
    if my_input == "":
      if current_fi is None:
        return (None, None)
      else:
        return (current_fi, "")

     # Manage relative path without current_fi
    if my_input[0] != "/" and current_fi is None:
      return (None, None)

    end_with_dot_or_doubledot = os.path.split(input)[1] in (".", "..")
    if end_with_dot_or_doubledot:  # Manage path ending with a dot or a double dot
      my_input = os.path.normpath(f"{my_input}a")
    else:
      my_input = os.path.normpath(f"{my_input}")

    # Build full path and normalize it (removing .. and .)
    if my_input[0] != "/":
      my_input = f"{current_fi.path}/{my_input}"

    # Search folder and extract start_text
    folder_names = StrPathUtil.split_path(my_input)
    folder_names = folder_names[1:]  # Remove first item which is ""
    if input[-1] == "/":  # Last part is a folder
      start_text = ""
    else:

      if end_with_dot_or_doubledot:  # Manage path ending with a dot or a double dot
        start_text = os.path.split(input)[1]
        # remove the last folder name which is ".a" or "..a"
        folder_names = folder_names[:-1]
      else:
        start_text = folder_names[-1]
        # remove the last folder name which is the start text
        folder_names = folder_names[:-1]

    search_folder = root_fi
    found = True
    for f in folder_names:
      if search_folder.is_direct_child_folder(f, True):
        search_folder = search_folder.get_direct_child_folder(f, True)
      else:
        found = False
        break

    if found:
      return (search_folder, start_text)
    else:
      return (None, None)


class MsFolderInfo(MsObject):

  @beartype
  def __init__(
          self,
          name: str,
          parent_path: str,
          mgc: MsGraphClient,
          id: str,
          size: int,
          child_count: int = None,
          parent=None,
          lmdt=None,
          cdt=None,
          is_root: bool = False):
    """
        Init folder info
        mgc   = MsGraphClient
    """
    super().__init__(parent, name, parent_path, id, size, lmdt, cdt, is_root)
    self.__mgc = mgc
    self.children_file = []
    self.children_folder = []
    self.children_other = []
    self.__dict_children_file = {}  # key = name
    self.__dict_children_folder = {}  # key = name
    self.__dict_children_other = {}  # key = name

    self.next_link_children = None

    self.child_count = child_count

    self.__children_retrieval_status = None    # None,"partial" or "all"

    self.__add_default_folder_info()

  def get_nb_retrieved_children(self):
    return (
      len(self.children_file)
      + len(self.children_folder)
      + len(self.children_other)
      )

  def update_parent(self, new_parent):
    super().update_parent(new_parent)
    self.__dict_children_folder[".."] = self.parent

  def _change_name_in_parent(self, new_name):
    if self.parent is not None:
      if self.name in self.parent.__dict_children_folder:
        self.parent.__dict_children_folder.pop(self.name)
        self.parent.__dict_children_folder[new_name] = self

  @beartype
  def remove_info_for_child(self, child: MsObject):
    if isinstance(child, MsFolderInfo):
      self.children_folder.remove(child)
      self.__dict_children_folder.pop(child.name)
    elif isinstance(child, MsFileInfo):
      self.children_file.remove(child)
      self.__dict_children_file.pop(child.name)
    else:  # isinstance(child, MsOtherInfo):
      self.children_other.remove(child)
      self.__dict_children_other.pop(child.name)

  def retrieve_children_info(
          self,
          recursive=False,
          depth=999,
          max_retrieved_children=200):
    lg.debug(
        f"[retrieve_children_info] {self.path} - depth = {depth} - "
        f"max_retrieved_children = {max_retrieved_children} -"
        f" - {self.get_nb_retrieved_children()} - {self.child_count=}")

    if depth >= 0 and (
        not self.children_retrieval_has_started()
        or (
          self.get_nb_retrieved_children() < self.child_count
          and self.get_nb_retrieved_children() < max_retrieved_children
        )
    ):
      nb_retrieved_children_start = self.get_nb_retrieved_children()

      try:
        if self.next_link_children is None:
          (ms_response, next_link) = self.__mgc.get_ms_response_for_children_from_id(
              self.ms_id)
        else:
          (ms_response, next_link) = self.__mgc.get_ms_response_for_children_from_link(
            self.next_link_children)
      except MsGraphException as mge:
        # Can occurs if folder name has changed
        lg.warning(f"[retrieve_children_info]Warning - Nothing received from link {mge.src_link}")
        return (None, None)

      self.next_link_children = next_link

      for c in ms_response:

        if not self.children_retrieval_has_started() and 'folder' in c:
          fi = ObjectInfoFactory.MsFolderFromMgcResponse(self.__mgc, c, self)
          self.__add_folder_info_if_necessary(fi)
          if recursive:
            fi.retrieve_children_info(
                recursive=recursive,
                depth=depth - 1,
                max_retrieved_children=max_retrieved_children)

        elif 'file' in c:
          fi = ObjectInfoFactory.MsFileInfoFromMgcResponse(self.__mgc, c, self)
          self.__add_file_info_if_necessary(fi)

        elif  'package' in c:
          fi = ObjectInfoFactory.MsOtherInfoFromMgcResponse(
              self.__mgc, c, self)
          self.__add_other_info_if_necessary(fi)

        # else:   - isFolder and folder already retrieved

      lg.debug(
          f"[retrieve_children_info] {self.path} - setting retrieval status")

      self.__children_retrieval_status = "partial" if self.next_link_children is not None else "all"

      if (
        self.next_link_children
        and self.get_nb_retrieved_children() < self.child_count
        and self.get_nb_retrieved_children() < max_retrieved_children
        and nb_retrieved_children_start != self.get_nb_retrieved_children()
      ):
        self.retrieve_children_info(recursive=recursive, depth=depth,
                                    max_retrieved_children=max_retrieved_children)

  def retrieve_children_info_next(
          self,
          recursive=False,
          depth=999):
    lg.debug(
        f"[retrieve_children_info_next] {self.path} - depth = {depth}")

    if depth > 0 and (self.__children_retrieval_status != "all"):

      (ms_response, next_link) = self.__mgc.get_ms_response_for_children_from_link(
          self.next_link_children)
      self.next_link_children = next_link

      for c in ms_response:
        isFolder = 'folder' in c
        if isFolder:
          fi = ObjectInfoFactory.MsFolderFromMgcResponse(self.__mgc, c, self)
          self.__add_folder_info_if_necessary(fi)
          if recursive:
            fi.retrieve_children_info(
                recursive=recursive,
                depth=depth - 1)

        else:
          fi = ObjectInfoFactory.MsFileInfoFromMgcResponse(self.__mgc, c, self)
          self.__add_file_info_if_necessary(fi)

      lg.debug(
          f"[retrieve_children_info_from_link] {self.next_link_children} - setting retrieval status")

      self.__children_retrieval_status = "partial" if self.next_link_children is not None else "all"

  def create_empty_subfolder(self, folder_name):
    folder_json = self.__mgc.create_folder(self.path, folder_name)
    if folder_json:
      new_folder_info = ObjectInfoFactory.MsFolderFromMgcResponse(
          mgc=self.__mgc,
          mgc_response_json=folder_json,
          parent=self
      )
      self.__add_folder_info_if_necessary(new_folder_info)
      new_folder_info.update_parent_after_arrival(
          self, new_folder_info.last_modified_datetime)
      if self.child_count is not None:
        self.child_count += 1
      return new_folder_info
    else:
      return None

  def __add_folder_info_if_necessary(self, folder_info):
    if folder_info.name not in self.__dict_children_folder:
      self.children_folder.append(folder_info)
      self.__dict_children_folder[folder_info.name] = folder_info

  def __add_default_folder_info(self):
    # add subfolder "." and ".."
    self.__dict_children_folder["."] = self
    self.__dict_children_folder[".."] = self.parent

  def __add_file_info_if_necessary(self, file_info):
    if file_info.name not in self.__dict_children_file:
      self.children_file.append(file_info)
      self.__dict_children_file[file_info.name] = file_info

  def __add_other_info_if_necessary(self, other_info):
    if other_info.name not in self.__dict_children_other:
      self.children_other.append(other_info)
      self.__dict_children_other[other_info.name] = other_info

  def add_object_info(self, object_info: MsObject):
    if isinstance(object_info, MsFolderInfo):
      self.__add_folder_info_if_necessary(object_info)
    elif isinstance(object_info, MsFileInfo):
      self.__add_file_info_if_necessary(object_info)
    else:  # isinstance(object_info, MsOtherInfo):
      self.__add_other_info_if_necessary(object_info)

  def get_direct_child_folder(
          self,
          folder_name,
          force_children_retrieval=False):
    if force_children_retrieval and not self.children_retrieval_has_started():
      self.retrieve_children_info()
    return self.__dict_children_folder[folder_name] if folder_name in self.__dict_children_folder else None

  def get_child_folder(
          self,
          relative_folder_path,
          force_children_retrieval=False):
    path_parts = relative_folder_path.split(os.sep)
    if path_parts[-1] == "":      # folder_path ends with a "/"
      path_parts = path_parts[:-1]
    search_folder = self
    for f in path_parts:
      if search_folder.is_direct_child_folder(f, force_children_retrieval):
        search_folder = search_folder.get_direct_child_folder(
            f, force_children_retrieval)
      else:
        return None
    return search_folder

  def get_direct_child_file(self, file_name, force_children_retrieval=False):
    if force_children_retrieval and not self.children_retrieval_has_started():
      self.retrieve_children_info()
    return self.__dict_children_file[file_name] if file_name in self.__dict_children_file else None

  def get_child_file(
          self,
          relative_file_path,
          force_children_retrieval=False) -> Optional["MsFileInfo"]:
    path_parts = relative_file_path.split(os.sep)
    search_folder = self
    i = 0
    while i < (len(path_parts) - 1):
      f = path_parts[i]
      if search_folder.is_direct_child_folder(f, force_children_retrieval):
        search_folder = search_folder.get_direct_child_folder(
            f, force_children_retrieval)
      else:
        return None
      i += 1
    if search_folder.is_direct_child_file(
            path_parts[-1], force_children_retrieval):
      return search_folder.get_direct_child_file(
          path_parts[-1], force_children_retrieval)

  def is_direct_child_folder(
          self,
          folder_name,
          force_children_retrieval=False):
    if force_children_retrieval and not self.children_retrieval_has_started():
      self.retrieve_children_info()
    return folder_name in self.__dict_children_folder

  def relative_path_is_a_folder(
          self,
          relative_folder_path,
          force_children_retrieval=False):
    return self.get_child_folder(
        relative_folder_path,
        force_children_retrieval) is not None

  def is_direct_child_file(self, file_name, force_children_retrieval=False):
    if force_children_retrieval and not self.children_retrieval_has_started():
      self.retrieve_children_info()
    return file_name in self.__dict_children_file

  def is_direct_child_other(self, other_name, force_children_retrieval=False):
    if force_children_retrieval and not self.children_retrieval_has_started():
      self.retrieve_children_info()
    return other_name in self.__dict_children_other

  def get_direct_child_other(self, other_name, force_children_retrieval=False):
    if force_children_retrieval and not self.children_retrieval_has_started():
      self.retrieve_children_info()
    return self.__dict_children_other[other_name] if other_name in self.__dict_children_other else None

  def get_child_other(
          self,
          relative_other_path,
          force_children_retrieval=False):
    path_parts = relative_other_path.split(os.sep)
    search_folder = self
    i = 0
    while i < (len(path_parts) - 1):
      f = path_parts[i]
      if search_folder.is_direct_child_folder(f, force_children_retrieval):
        search_folder = search_folder.get_direct_child_folder(
            f, force_children_retrieval)
      else:
        return None
      i += 1
    if search_folder.is_direct_child_other(
            path_parts[-1], force_children_retrieval):
      return search_folder.get_direct_child_other(
          path_parts[-1], force_children_retrieval)

  def relative_path_is_a_file(
          self,
          relative_file_path,
          force_children_retrieval=False):
    return self.get_child_file(
        relative_file_path,
        force_children_retrieval) is not None

  def relative_path_is_other(  # Child but not a file neither a folder
          self,
          relative_path,
          force_children_retrieval=False):
    return self.get_child_other(
        relative_path,
        force_children_retrieval) is not None

  def children_retrieval_has_started(self):
    return self.__children_retrieval_status == "all" or self.__children_retrieval_status == "partial"

  def children_retrieval_is_completed(self):
    return self.__children_retrieval_status == "all"

  def __str__(self):
    status_children = "<children ok>" if self.children_retrieval_is_completed() else ""

    fname = f"{self.name}/" if len(self.name) < 25 else f"{self.name[:20]}.../"
    result = f"{self.size:>20,}  {fname:<25}  {self.child_count:>6}  {status_children}"
    return result

  def str_full_details(self):
    result = (
        f"Folder - {self.path[1:]}\n"
        f"  name                       = {self.name}\n"
        f"  id                         = {self.ms_id}\n"
        f"  size                       = {self.size}\n"
        f"  childcount                 = {self.child_count}\n"
        f"  lastModifiedDateTime       = {self.last_modified_datetime}\n"
        f"  creationDateTime           = {self.creation_datetime}\n"
        f"  childrenRetrievalStatus    = {self.__children_retrieval_status}\n"
    )

    return result

  def __repr__(self):
    return f"Folder({self.name})"


class MsFileInfo(MsObject):
  def __init__(self, name, parent_path, mgc, file_id,
               size, qxh, s1h, cdt, lmdt, parent=None):
    # qxh = quickxorhash
    super().__init__(parent, name, parent_path, file_id, size, lmdt, cdt)
    self.mgc = mgc
    self.sha1hash = s1h
    self.qxh = qxh

  def _change_name_in_parent(self, new_name):
    if self.parent is not None:
      if self.name in self.parent._MsFolderInfo__dict_children_file:
        self.parent._MsFolderInfo__dict_children_file.pop(self.name)
        self.parent._MsFolderInfo__dict_children_file[new_name] = self

  def __str__(self):
    fname = f"{self.name}" if len(self.name) < 45 else f"{self.name[:40]}..."
    fmdt = self.last_modified_datetime.strftime("%Y-%m-%d %H:%M:%S")
    result = f"{self.size:>20,}  {fname:<45}  {fmdt}  "
    return result

  def str_full_details(self):
    result = (
        f"File - '{self.name}'\n"
        f"  name                  = {self.name}\n"
        f"  full_path             = {self.path}\n"
        f"  id                    = {self.ms_id:>20}\n"
        f"  size                  = {self.size:,}\n"
        f"  quickXorHash          = {self.qxh}\n"
        f"  sha1Hash              = {self.sha1hash}\n"
        f"  creationDateTime      = {self.creation_datetime}\n"
        f"  lastModifiedDateTime  = {self.last_modified_datetime}"
    )

    return result

  def __repr__(self):
    return f"File({self.name})"


class MsOtherInfo(MsObject):

  def __init__(self, name, parent_path, mgc, ms_id,
               size, cdt, lmdt, type_other, parent=None):
    super().__init__(parent, name, parent_path, ms_id, size, lmdt, cdt)
    self.mgc = mgc
    self.type_other = type_other  # "type" is a reserved keyword

  def _change_name_in_parent(self, new_name):
    if self.parent is not None:
      if self.name in self.parent._MsFolderInfo__dict_children_other:
        self.parent._MsFolderInfo__dict_children_other.pop(self.name)
        self.parent._MsFolderInfo__dict_children_other[new_name] = self

  def __str__(self):
    fname = f"{self.name}" if len(self.name) < 45 else f"{self.name[:40]}..."
    fmdt = self.last_modified_datetime.strftime("%Y-%m-%d %H:%M:%S")
    result = f"{self.size:>20,}  {fname:<45}  {fmdt}  "
    return result

  def str_full_details(self):
    result = (
        f"Object - '{self.name}'\n"
        f"  type                  = {self.type_other}\n"
        f"  name                  = {self.name}\n"
        f"  full_path             = {self.path}\n"
        f"  id                    = {self.ms_id:>20}\n"
        f"  size                  = {self.size:,}\n"
        f"  creationDateTime      = {self.creation_datetime}\n"
        f"  lastModifiedDateTime  = {self.last_modified_datetime}"
    )

    return result

  def __repr__(self):
    return f"Other({self.name})"


class DictMsObject():
  __dict_already_discovered_object = {}
  __lock_dict = Lock()  # only used for removing object from dict which is unsafe (1)
  # (1) https://superfastpython.com/thread-safe-dictionary-in-python/

  @staticmethod
  def get(ms_id) -> Optional[MsObject]:
    with DictMsObject.__lock_dict:
      if ms_id in DictMsObject.__dict_already_discovered_object:
        result = DictMsObject.__dict_already_discovered_object[ms_id]
      else:
        result = None
    return result

  @staticmethod
  def remove(ms_id):
    with DictMsObject.__lock_dict:
      DictMsObject.__dict_already_discovered_object.pop(ms_id)

  @staticmethod
  @beartype
  def add_or_get_update(obj: MsObject):
    if obj.ms_id in DictMsObject.__dict_already_discovered_object:
      obj_dict = DictMsObject.__dict_already_discovered_object[obj.ms_id]
      if isinstance(obj, MsFolderInfo):
        ObjectInfoFactory.UpdateMsFolderInfo(obj_dict, obj)
        result = obj_dict
      elif isinstance(obj, MsFileInfo):
        ObjectInfoFactory.UpdateMsFileInfo(obj_dict, obj)
        result = obj_dict
      else:
        lg.warn("[oif.add_or_update] Object type not considered")
        result = None

    else:
      DictMsObject.__dict_already_discovered_object[obj.ms_id] = obj
      result = obj

    return result


class ObjectInfoFactory:

  class ObjectRetrievalException(Exception):

    def __init__(self, error_code):
      super().__init__(
          f"Object Retrieval Exception, error_code = {error_code}")
      self.error_code = error_code

  @staticmethod
  def get_object_info_from_mgc_response(
          mgc,
          mgc_response,
          parent=None,
          no_warn_if_no_parent=False,
          no_update_and_get_from_global_dict=False) -> MsObject:
    """
      Return MsObject from its JSON representation sent by MS Graph.
      An ObjectRetrievalException is raised in case of error.
    """
    if 'error' in mgc_response:
      raise ObjectInfoFactory.ObjectRetrievalException(
          mgc_response['error']['code'])

    if ('folder' in mgc_response):
      mso = ObjectInfoFactory.MsFolderFromMgcResponse(
          mgc,
          mgc_response,
          parent,
          no_warn_if_no_parent,
          no_update_and_get_from_global_dict)
    elif ('file' in mgc_response):
      mso = ObjectInfoFactory.MsFileInfoFromMgcResponse(
          mgc,
          mgc_response,
          parent,
          no_warn_if_no_parent,
          no_update_and_get_from_global_dict)
    else:
      mso = ObjectInfoFactory.MsOtherInfoFromMgcResponse(
          mgc,
          mgc_response,
          parent,
          no_warn_if_no_parent,
          no_update_and_get_from_global_dict)
    return mso

  @staticmethod
  def get_object_info_from_path(
          mgc: MsGraphClient,
          path,
          parent=None,
          no_warn_if_no_parent=False,
          no_update_and_get_from_global_dict=False) -> MsObject:
    """
      Return MsObject from its path.
      An ObjectRetrievalException is raised in case of error.
    """
    lg.debug(f"[get_object_info_from_path]get path '{path}'")
    r = mgc.get_ms_response_from_path(path)
    if r is None:
      raise ObjectInfoFactory.ObjectRetrievalException(
          'CUSTOM_PATH_NOT_FOUND')

    return ObjectInfoFactory.get_object_info_from_mgc_response(
        mgc, r, parent, no_warn_if_no_parent, no_update_and_get_from_global_dict)


  @staticmethod
  def get_object_info_from_id(
          mgc, ms_id, parent=None,
          no_warn_if_no_parent=False,
          no_update_and_get_from_global_dict=False) -> MsObject:
    """
      Return MsObject from its id.
      An ObjectRetrievalException is raised in case of error.
    """
    r = mgc.get_ms_response_from_id(ms_id)
    return ObjectInfoFactory.get_object_info_from_mgc_response(
        mgc, r, parent, no_warn_if_no_parent, no_update_and_get_from_global_dict)

  @staticmethod
  def MsFolderFromMgcResponse(
          mgc,
          mgc_response_json,
          parent=None,
          no_warn_if_no_parent=False,
          no_update_and_get_from_global_dict=False) -> MsFolderInfo:

    # Workaround following what seems to be a bug. Space is replaced by "%20" sequence
    #   in mgc_response when parent name contains a space
    if parent is not None:
      parent_path = parent.path
      is_root = False
    else:
      if not no_warn_if_no_parent:
        lg.warning(
            "[MsFolderFromMgcResponse]No parent folder to create a folder info")
      if 'parentReference' in mgc_response_json and 'path' in mgc_response_json[
              'parentReference']:
        parent_path = urllib.parse.unquote(
            mgc_response_json['parentReference']['path'][12:])
        is_root = False
      else:
        parent_path = ""
        is_root = True

    # full_path = "" if "root" in mgc_response_json else
    # f"{parent_path}/{mgc_response_json['name']}"
    ms_id = mgc_response_json['id']

    result = MsFolderInfo(
        parent_path=parent_path,
        name=mgc_response_json['name'],
        mgc=mgc,
        id=ms_id,
        child_count=mgc_response_json['folder']['childCount'],
        size=mgc_response_json['size'],
        parent=parent,
        lmdt=utc_dt_from_str_ms_datetime(
            mgc_response_json['lastModifiedDateTime']),
        cdt=utc_dt_from_str_ms_datetime(
            mgc_response_json['createdDateTime']),
        is_root=is_root)
    if parent is not None:
      parent._MsFolderInfo__add_folder_info_if_necessary(result)

    if not no_update_and_get_from_global_dict:
      result = DictMsObject.add_or_get_update(result)
    return result

  @staticmethod
  @beartype
  def UpdateMsFolderInfo(
          fi_to_be_updated: MsFolderInfo,
          fi_reference: MsFolderInfo,
          update_child_count=True):
    fi_to_be_updated.set_name(fi_reference.name)
    fi_to_be_updated.set_size(fi_reference.size)

    fi_to_be_updated.last_modified_datetime = fi_reference.last_modified_datetime
    fi_to_be_updated.creation_datetime = fi_reference.creation_datetime
    if update_child_count:
      fi_to_be_updated.child_count = fi_reference.child_count

  @staticmethod
  @beartype
  def UpdateMsFileInfo(
          fi_to_be_updated: MsFileInfo,
          fi_reference: MsFileInfo):
    fi_to_be_updated.set_name(fi_reference.name)
    fi_to_be_updated.set_size(fi_reference.size)

    fi_to_be_updated.last_modified_datetime = fi_reference.last_modified_datetime
    fi_to_be_updated.creation_datetime = fi_reference.creation_datetime
    fi_to_be_updated.qxh = fi_reference.qxh
    fi_to_be_updated.sha1hash = fi_reference.sha1hash

  @staticmethod
  def MsFileInfoFromMgcResponse(
          mgc,
          mgc_response_json,
          parent=None,
          no_warn_if_no_parent=False,
          no_update_and_get_from_global_dict=False) -> MsFileInfo:
    if parent is None and not no_warn_if_no_parent:
      lg.warning(
          "[MsFileFromMgcResponse]No parent folder to create a file info")
    if 'hashes' not in mgc_response_json['file']:
      qxh = None
      sha1hash = None
    else:
      mgc_hashes = mgc_response_json['file']['hashes']
      qxh = (mgc_hashes['quickXorHash']
             if 'quickXorHash' in mgc_hashes else None)
      sha1hash = (mgc_hashes['sha1Hash']
                  if 'sha1Hash' in mgc_hashes else None)
    ms_id = mgc_response_json['id']
    result = MsFileInfo(
        mgc_response_json['name'],
        urllib.parse.unquote(mgc_response_json['parentReference']['path'][13:]),
        mgc,
        ms_id, mgc_response_json['size'],
        qxh, sha1hash,
        utc_dt_from_str_ms_datetime(
            mgc_response_json['createdDateTime']),
        utc_dt_from_str_ms_datetime(
            mgc_response_json['lastModifiedDateTime']),
        parent=parent)

    if parent is not None:
      parent._MsFolderInfo__add_file_info_if_necessary(result)

    if not no_update_and_get_from_global_dict:
      result = DictMsObject.add_or_get_update(result)
    return result

  @staticmethod
  def MsOtherInfoFromMgcResponse(
          mgc,
          mgc_response_json,
          parent=None,
          no_warn_if_no_parent=False,
          no_update_and_get_from_global_dict=False) -> MsOtherInfo:
    if parent is None and not no_warn_if_no_parent:
      lg.warning(
          "[MsOtherInfoFromMgcResponse]No parent folder to create a other info")

    ms_id = mgc_response_json['id']
    if ('package' in mgc_response_json
            and 'type' in mgc_response_json['package']):
      type_other = mgc_response_json['package']['type']
    else:
      type_other = 'unknown'

    result = MsOtherInfo(
        mgc_response_json['name'],
        urllib.parse.unquote(mgc_response_json['parentReference']['path'][13:]),
        mgc,
        ms_id, mgc_response_json['size'],
        utc_dt_from_str_ms_datetime(
            mgc_response_json['createdDateTime']),
        utc_dt_from_str_ms_datetime(
            mgc_response_json['lastModifiedDateTime']),
        type_other,
        parent=parent)

    if parent is not None:
      parent._MsFolderInfo__add_other_info_if_necessary(result)

    if not no_update_and_get_from_global_dict:
      result = DictMsObject.add_or_get_update(result)
    return result
